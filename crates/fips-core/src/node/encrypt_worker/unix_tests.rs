#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use crate::transport::udp::socket::UdpRawSocket;
    use ring::aead::{LessSafeKey, UnboundKey};
    use std::net::UdpSocket;

    fn test_cipher(byte: u8) -> LessSafeKey {
        let key_bytes = [byte; 32];
        let unbound =
            UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).expect("build key");
        LessSafeKey::new(unbound)
    }

    fn seal_cost_iterations() -> usize {
        std::env::var("FIPS_SEAL_COST_ITERS")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(100_000)
            .max(1)
    }

    fn seal_cost_payload_len() -> usize {
        std::env::var("FIPS_SEAL_COST_PAYLOAD")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(1150)
            .max(1)
    }

    fn fmp_only_wire_buf(payload_len: usize, seed: u8) -> Vec<u8> {
        let mut wire_buf =
            Vec::with_capacity(ESTABLISHED_HEADER_SIZE + payload_len + crate::noise::TAG_SIZE);
        wire_buf.extend_from_slice(&[seed; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + payload_len, seed ^ 0xa5);
        wire_buf
    }

    fn fsp_fmp_wire_buf(payload_len: usize, seed: u8) -> (Vec<u8>, usize, usize) {
        let mut wire_buf = Vec::with_capacity(
            ESTABLISHED_HEADER_SIZE
                + FSP_HEADER_SIZE
                + payload_len
                + crate::noise::TAG_SIZE
                + crate::noise::TAG_SIZE,
        );
        wire_buf.extend_from_slice(&[seed; ESTABLISHED_HEADER_SIZE]);
        let fsp_aad_offset = wire_buf.len();
        wire_buf.extend_from_slice(&[seed ^ 0x33; FSP_HEADER_SIZE]);
        let fsp_plaintext_offset = wire_buf.len();
        wire_buf.resize(fsp_plaintext_offset + payload_len, seed ^ 0xa5);
        (wire_buf, fsp_aad_offset, fsp_plaintext_offset)
    }

    #[test]
    #[ignore = "diagnostic microbench; run with --ignored --nocapture"]
    fn measure_worker_seal_cost_fmp_only_vs_fsp_fmp() {
        let iters = seal_cost_iterations();
        let payload_len = seal_cost_payload_len();
        let fmp_cipher = test_cipher(0x11);
        let fsp_cipher = test_cipher(0x22);

        // Keep allocation out of the measured loop; production workers receive
        // prebuilt buffers and spend their hot time in `seal_wire_packet`.
        let mut fmp_wire_buf = fmp_only_wire_buf(payload_len, 0x44);
        let fmp_plain_len = fmp_wire_buf.len();
        let mut fmp_bytes = 0usize;
        let fmp_started = std::time::Instant::now();
        for i in 0..iters {
            fmp_wire_buf.truncate(fmp_plain_len);
            SealedSendPacket::seal_wire_packet(
                fmp_cipher.clone().into(),
                i as u64,
                &mut fmp_wire_buf,
                None,
            )
            .expect("FMP-only seal");
            fmp_bytes = fmp_bytes.wrapping_add(std::hint::black_box(fmp_wire_buf.len()));
        }
        let fmp_elapsed = fmp_started.elapsed();

        let (mut dual_wire_buf, fsp_aad_offset, fsp_plaintext_offset) =
            fsp_fmp_wire_buf(payload_len, 0x55);
        let dual_plain_len = dual_wire_buf.len();
        let mut dual_bytes = 0usize;
        let dual_started = std::time::Instant::now();
        for i in 0..iters {
            dual_wire_buf.truncate(dual_plain_len);
            SealedSendPacket::seal_wire_packet(
                fmp_cipher.clone().into(),
                i as u64,
                &mut dual_wire_buf,
                Some(FspSealJob {
                    cipher: fsp_cipher.clone().into(),
                    counter: i as u64,
                    aad_offset: fsp_aad_offset,
                    plaintext_offset: fsp_plaintext_offset,
                }),
            )
            .expect("FSP+FMP seal");
            dual_bytes = dual_bytes.wrapping_add(std::hint::black_box(dual_wire_buf.len()));
        }
        let dual_elapsed = dual_started.elapsed();

        let fmp_ns = fmp_elapsed.as_nanos() as f64 / iters as f64;
        let dual_ns = dual_elapsed.as_nanos() as f64 / iters as f64;
        let fmp_gbps = (fmp_bytes as f64 * 8.0) / fmp_elapsed.as_secs_f64() / 1_000_000_000.0;
        let dual_gbps = (dual_bytes as f64 * 8.0) / dual_elapsed.as_secs_f64() / 1_000_000_000.0;
        println!(
            "seal_cost payload_len={payload_len} iters={iters} fmp_only_ns_per_packet={fmp_ns:.1} fsp_fmp_ns_per_packet={dual_ns:.1} overhead_ns_per_packet={:.1} fmp_only_gbps={fmp_gbps:.2} fsp_fmp_gbps={dual_gbps:.2}",
            dual_ns - fmp_ns,
        );
    }

    fn queued_test_job_classified(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
        bulk_endpoint_data: bool,
    ) -> QueuedFmpSendJob {
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + payload_len + 16);
        wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + payload_len, 0);
        QueuedFmpSendJob::direct(FmpSendJob {
            cipher: cipher.clone().into(),
            counter: 0,
            wire_buf,
            fsp_seal: None,
            send_target: SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_addr,
            ),
            endpoint_flow_dispatch_key: None,
            bulk_endpoint_data,
            drop_on_backpressure: bulk_endpoint_data,
            scheduling_weight: DEFAULT_SEND_WEIGHT,
            queued_at: None,
        })
    }

    fn queued_test_job(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
    ) -> QueuedFmpSendJob {
        queued_test_job_classified(socket, cipher, dest_addr, payload_len, true)
    }

    #[test]
    fn encrypt_worker_shard_owns_batch_drain_and_flush_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(3);
            let dest: SocketAddr = "127.0.0.1:10034".parse().unwrap();
            let mut shard = EncryptWorkerShard::new(7, 2);
            let mut recv_max = 0;
            let mut flush_count = 0;

            assert!(shard.drain_and_flush_once(
                |batch, max| {
                    recv_max = max;
                    assert!(batch.is_empty());
                    batch.push(queued_test_job(socket.clone(), &cipher, dest, 32));
                    batch.push(queued_test_job(socket.clone(), &cipher, dest, 48));
                    Some(FmpWorkerBatchStats::from_batch(batch))
                },
                |batch| {
                    flush_count += 1;
                    assert_eq!(batch.len(), 2);
                    Err(Box::new(std::io::Error::other("forced flush failure"))
                        as Box<dyn std::error::Error + Send + Sync>)
                },
            ));
            assert_eq!(recv_max, 2);
            assert_eq!(flush_count, 1);
            assert_eq!(
                shard.batch_len(),
                0,
                "the shard owns and clears the local batch after flush failure"
            );

            assert!(!shard.drain_and_flush_once(
                |batch, max| {
                    assert_eq!(max, 2);
                    assert!(batch.is_empty());
                    None
                },
                |_batch| panic!("flush must not run when receive returns closed"),
            ));
        });
    }

    #[test]
    fn encrypt_worker_shard_preserves_dequeue_order_inside_local_batch() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(7);
            let dest: SocketAddr = "127.0.0.1:10035".parse().unwrap();
            let mut shard = EncryptWorkerShard::new(3, 4);

            assert!(shard.drain_and_flush_once(
                |batch, _max| {
                    batch.push(queued_test_job_classified(
                        socket.clone(),
                        &cipher,
                        dest,
                        101,
                        true,
                    ));
                    batch.push(queued_test_job_classified(
                        socket.clone(),
                        &cipher,
                        dest,
                        11,
                        false,
                    ));
                    batch.push(queued_test_job_classified(
                        socket.clone(),
                        &cipher,
                        dest,
                        102,
                        true,
                    ));
                    batch.push(queued_test_job_classified(socket, &cipher, dest, 12, false));
                    Some(FmpWorkerBatchStats::from_batch(batch))
                },
                |batch| {
                    let lanes: Vec<_> = batch.iter().map(QueuedFmpSendJob::queue_lane).collect();
                    assert_eq!(
                        lanes,
                        vec![
                            EncryptWorkerLane::Bulk,
                            EncryptWorkerLane::Priority,
                            EncryptWorkerLane::Bulk,
                            EncryptWorkerLane::Priority,
                        ],
                        "once a worker owns a local batch it must preserve dequeue order for TCP-shaped flows"
                    );
                    let payload_lens: Vec<_> = batch
                        .iter()
                        .map(|job| job.job.wire_buf.len() - ESTABLISHED_HEADER_SIZE)
                        .collect();
                    assert_eq!(
                        payload_lens,
                        vec![101, 11, 102, 12],
                        "local worker batching must not reorder small endpoint-data packets ahead of earlier bulk packets"
                    );
                    let stats = FmpWorkerBatchStats::from_batch(batch);
                    assert_eq!(stats.priority_packets, 2);
                    assert_eq!(stats.bulk_packets, 2);
                    batch.clear();
                    Ok(())
                },
            ));
        });
    }

    #[test]
    fn sealed_send_packet_owns_target_wire_and_drop_policy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(4);
            let counter = 44;
            let dest: SocketAddr = "127.0.0.1:10035".parse().unwrap();
            let target = SelectedSendTarget::new(
                socket.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let target_key = target.key();
            let header = [0x42; ESTABLISHED_HEADER_SIZE];
            let plaintext = b"sealed owner packet";
            let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + plaintext.len() + 16);
            wire_buf.extend_from_slice(&header);
            wire_buf.extend_from_slice(plaintext);

            let sealed = SealedSendPacket::from_job(FmpSendJob {
                cipher: cipher.clone().into(),
                counter,
                wire_buf,
                fsp_seal: None,
                send_target: target,
                endpoint_flow_dispatch_key: None,
                bulk_endpoint_data: true,
                drop_on_backpressure: false,
                scheduling_weight: DEFAULT_SEND_WEIGHT,
                queued_at: None,
            })
            .expect("seal packet");

            assert_eq!(sealed.target_key(), target_key);
            assert!(
                !sealed.drop_on_backpressure(),
                "the sealed packet owns the original drop policy"
            );
            assert_eq!(
                sealed.wire_packet().len(),
                ESTABLISHED_HEADER_SIZE + plaintext.len() + crate::noise::TAG_SIZE
            );
            assert_eq!(&sealed.wire_packet()[..ESTABLISHED_HEADER_SIZE], &header);
            let opened = crate::noise::open(
                Some(&cipher),
                counter,
                &header,
                &sealed.wire_packet()[ESTABLISHED_HEADER_SIZE..],
            )
            .expect("open sealed packet");
            assert_eq!(opened, plaintext);

            let invalid_target = SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let invalid = SealedSendPacket::from_job(FmpSendJob {
                cipher: cipher.into(),
                counter: counter + 1,
                wire_buf: vec![0; ESTABLISHED_HEADER_SIZE + 8],
                fsp_seal: Some(FspSealJob {
                    cipher: test_cipher(5).into(),
                    counter: 1,
                    aad_offset: ESTABLISHED_HEADER_SIZE,
                    plaintext_offset: ESTABLISHED_HEADER_SIZE,
                }),
                send_target: invalid_target,
                endpoint_flow_dispatch_key: None,
                bulk_endpoint_data: true,
                drop_on_backpressure: true,
                scheduling_weight: DEFAULT_SEND_WEIGHT,
                queued_at: None,
            });
            assert!(matches!(invalid, Err(SealPacketError::InvalidFspLayout)));
        });
    }

    #[test]
    fn encrypt_worker_lane_policy_keeps_endpoint_bulk_explicit() {
        assert_eq!(
            encrypt_worker_lane_for_endpoint_data(false),
            EncryptWorkerLane::Priority
        );
        assert_eq!(
            encrypt_worker_lane_for_endpoint_data(true),
            EncryptWorkerLane::Bulk
        );
    }

    #[test]
    fn encrypt_worker_queue_wait_stage_follows_lane_policy() {
        assert_eq!(
            fmp_worker_queue_wait_stage_for_lane(EncryptWorkerLane::Priority),
            crate::perf_profile::Stage::FmpWorkerPriorityQueueWait
        );
        assert_eq!(
            fmp_worker_queue_wait_stage_for_lane(EncryptWorkerLane::Bulk),
            crate::perf_profile::Stage::FmpWorkerBulkQueueWait
        );
    }

    #[test]
    fn worker_batch_size_parse_stays_within_sender_accounting_limit() {
        assert_eq!(parse_worker_batch_size(Some("0"), 32), 1);
        assert_eq!(parse_worker_batch_size(Some("999"), 32), 64);
        assert_eq!(parse_worker_batch_size(Some("17"), 32), 17);
        assert_eq!(
            parse_worker_batch_size(Some("not-a-number"), 31),
            31,
            "invalid env values should keep the supplied platform default"
        );
    }

    #[test]
    fn worker_bulk_channel_default_is_latency_bounded() {
        assert_eq!(
            parse_worker_channel_cap(None, DEFAULT_WORKER_CHANNEL_CAP),
            256
        );
        assert_eq!(
            parse_worker_channel_cap(Some("not-a-number"), DEFAULT_WORKER_CHANNEL_CAP),
            256,
            "invalid env values should keep the tuned default"
        );
        assert_eq!(
            parse_worker_channel_cap(Some("0"), DEFAULT_WORKER_CHANNEL_CAP),
            1
        );
        assert_eq!(
            parse_worker_channel_cap(Some("999999"), DEFAULT_WORKER_CHANNEL_CAP),
            32768
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            parse_worker_channel_cap(None, DEFAULT_WORKER_PRIORITY_CHANNEL_CAP),
            1024,
            "control reserve must remain independent from bulk queue tuning"
        );
    }

    #[test]
    fn queued_fmp_send_job_owns_lane_and_target_key() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(6);
            let dest: SocketAddr = "127.0.0.1:10036".parse().unwrap();

            fn make_job(
                socket: AsyncUdpSocket,
                cipher: LessSafeKey,
                dest: SocketAddr,
                bulk_endpoint_data: bool,
            ) -> FmpSendJob {
                let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + 32 + 16);
                wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
                wire_buf.resize(ESTABLISHED_HEADER_SIZE + 32, 0);
                FmpSendJob {
                    cipher: cipher.into(),
                    counter: 7,
                    wire_buf,
                    fsp_seal: None,
                    send_target: SelectedSendTarget::new(
                        socket,
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        None,
                        dest,
                    ),
                    endpoint_flow_dispatch_key: None,
                    bulk_endpoint_data,
                    drop_on_backpressure: bulk_endpoint_data,
                    scheduling_weight: DEFAULT_SEND_WEIGHT,
                    queued_at: None,
                }
            }

            let priority_target = SelectedSendTarget::new(
                socket.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let priority_key = priority_target.key();
            let mut priority_job = make_job(socket.clone(), cipher.clone(), dest, false);
            priority_job.send_target = priority_target;
            let priority = QueuedFmpSendJob::direct(priority_job);
            assert_eq!(priority.queue_lane(), EncryptWorkerLane::Priority);
            assert_eq!(
                priority.target_key(),
                priority_key,
                "queued worker messages own the selected target key"
            );
            #[cfg(not(target_os = "macos"))]
            assert_eq!(priority.flow_key(), priority_key);

            let bulk = QueuedFmpSendJob::direct(make_job(socket, cipher, dest, true));
            assert_eq!(bulk.queue_lane(), EncryptWorkerLane::Bulk);
            assert_eq!(
                bulk.target_key(),
                priority_key,
                "same selected socket and destination keep the same queued key"
            );
        });
    }

    #[test]
    fn queued_target_key_survives_seal_and_batch_grouping() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let cipher = test_cipher(7);
            let dest: SocketAddr = "127.0.0.1:10037".parse().unwrap();
            let target = SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let target_key = target.key();
            let counter = 13;
            let header = [0x23; ESTABLISHED_HEADER_SIZE];
            let plaintext = b"queued key survives";
            let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + plaintext.len() + 16);
            wire_buf.extend_from_slice(&header);
            wire_buf.extend_from_slice(plaintext);

            let queued = QueuedFmpSendJob::direct(FmpSendJob {
                cipher: cipher.clone().into(),
                counter,
                wire_buf,
                fsp_seal: None,
                send_target: target,
                endpoint_flow_dispatch_key: None,
                bulk_endpoint_data: true,
                drop_on_backpressure: true,
                scheduling_weight: DEFAULT_SEND_WEIGHT,
                queued_at: None,
            });
            assert_eq!(queued.target_key(), target_key);

            let sealed = SealedSendPacket::from_queued(queued).expect("seal packet");
            assert_eq!(
                sealed.target_key(),
                target_key,
                "sealing must consume the queued message's selected key"
            );
            let (send_target, sealed_key, wire_packet, bulk_endpoint_data, drop_on_backpressure) =
                sealed.into_parts();
            assert_eq!(sealed_key, target_key);
            assert!(bulk_endpoint_data);
            assert!(drop_on_backpressure);

            let opened = crate::noise::open(
                Some(&cipher),
                counter,
                &header,
                &wire_packet[ESTABLISHED_HEADER_SIZE..],
            )
            .expect("open sealed packet");
            assert_eq!(opened, plaintext);

            let mut groups = Vec::new();
            push_selected_send_batch(
                &mut groups,
                send_target,
                sealed_key,
                wire_packet,
                drop_on_backpressure,
            );
            assert_eq!(groups.len(), 1);
            assert_eq!(
                groups[0].target_key(),
                target_key,
                "batch grouping must use the sealed packet's queued key"
            );
            assert_eq!(groups[0].wire_packets.len(), 1);
        });
    }

    #[test]
    fn fsp_preseal_runs_before_outer_fmp_seal() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
            recv.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .expect("set_read_timeout");
            let recv_addr = recv.local_addr().expect("recv local_addr");
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let send_sock = raw.into_async().expect("into_async");

            let fmp_cipher = test_cipher(1);
            let fsp_cipher = test_cipher(2);
            let fmp_counter = 11;
            let fsp_counter = 22;
            let fmp_header = [0xA5; ESTABLISHED_HEADER_SIZE];
            let fsp_header = [0x5A; FSP_HEADER_SIZE];
            let fsp_plaintext = b"inner payload";

            let mut wire_buf = Vec::with_capacity(
                ESTABLISHED_HEADER_SIZE
                    + FSP_HEADER_SIZE
                    + fsp_plaintext.len()
                    + crate::noise::TAG_SIZE
                    + crate::noise::TAG_SIZE,
            );
            wire_buf.extend_from_slice(&fmp_header);
            let fsp_aad_offset = wire_buf.len();
            wire_buf.extend_from_slice(&fsp_header);
            let fsp_plaintext_offset = wire_buf.len();
            wire_buf.extend_from_slice(fsp_plaintext);

            let expected_wire_len = ESTABLISHED_HEADER_SIZE
                + FSP_HEADER_SIZE
                + fsp_plaintext.len()
                + crate::noise::TAG_SIZE
                + crate::noise::TAG_SIZE;
            let mut batch = vec![FmpSendJob {
                cipher: fmp_cipher.clone().into(),
                counter: fmp_counter,
                wire_buf,
                fsp_seal: Some(FspSealJob {
                    cipher: fsp_cipher.clone().into(),
                    counter: fsp_counter,
                    aad_offset: fsp_aad_offset,
                    plaintext_offset: fsp_plaintext_offset,
                }),
                send_target: SelectedSendTarget::new(
                    send_sock,
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    None,
                    recv_addr,
                ),
                endpoint_flow_dispatch_key: None,
                bulk_endpoint_data: true,
                drop_on_backpressure: true,
                scheduling_weight: DEFAULT_SEND_WEIGHT,
                queued_at: None,
            }];

            flush_direct_batch_sync(&mut batch).expect("flush ok");
            assert!(batch.is_empty(), "flush must drain the batch");

            let mut buf = [0u8; 256];
            let (len, _) = recv.recv_from(&mut buf).expect("recv");
            assert_eq!(len, expected_wire_len);
            assert_eq!(&buf[..ESTABLISHED_HEADER_SIZE], &fmp_header);

            let outer_plaintext = crate::noise::open(
                Some(&fmp_cipher),
                fmp_counter,
                &fmp_header,
                &buf[ESTABLISHED_HEADER_SIZE..len],
            )
            .expect("outer open");
            assert_eq!(&outer_plaintext[..FSP_HEADER_SIZE], &fsp_header);
            let inner_plaintext = crate::noise::open(
                Some(&fsp_cipher),
                fsp_counter,
                &outer_plaintext[..FSP_HEADER_SIZE],
                &outer_plaintext[FSP_HEADER_SIZE..],
            )
            .expect("inner open");
            assert_eq!(inner_plaintext, fsp_plaintext);
        });
    }

    #[test]
    fn selected_send_batch_owns_target_fifo_and_drop_policy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw_a = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket a");
            let socket_a = raw_a.into_async().expect("into_async a");
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket b");
            let socket_b = raw_b.into_async().expect("into_async b");
            let dest_a: SocketAddr = "127.0.0.1:10029".parse().unwrap();
            let dest_b: SocketAddr = "127.0.0.1:10030".parse().unwrap();

            let target_a = SelectedSendTarget::new(
                socket_a.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_target_a = SelectedSendTarget::new(
                socket_a.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_target_a_droppable_again = SelectedSendTarget::new(
                socket_a.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_target_a_droppable_after_control = SelectedSendTarget::new(
                socket_a.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_dest_different_socket = SelectedSendTarget::new(
                socket_b,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_a,
            );
            let same_socket_different_dest = SelectedSendTarget::new(
                socket_a,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_b,
            );

            let key_a = target_a.key();
            let key_other_socket = same_dest_different_socket.key();
            let key_other_dest = same_socket_different_dest.key();
            assert_ne!(
                key_a, key_other_socket,
                "same sockaddr on a different socket is a different send batch"
            );
            assert_ne!(
                key_a, key_other_dest,
                "same socket to a different sockaddr is a different send batch"
            );

            let mut groups = Vec::new();
            push_selected_send_batch(&mut groups, target_a, key_a, vec![1], true);
            push_selected_send_batch(
                &mut groups,
                same_dest_different_socket,
                key_other_socket,
                vec![2],
                true,
            );
            push_selected_send_batch(
                &mut groups,
                same_target_a_droppable_again,
                key_a,
                vec![3],
                true,
            );
            push_selected_send_batch(&mut groups, same_target_a, key_a, vec![4], false);
            push_selected_send_batch(
                &mut groups,
                same_target_a_droppable_after_control,
                key_a,
                vec![5],
                true,
            );
            push_selected_send_batch(
                &mut groups,
                same_socket_different_dest,
                key_other_dest,
                vec![6],
                true,
            );

            assert_eq!(groups.len(), 6);
            assert_eq!(groups[0].target_key(), key_a);
            assert_eq!(groups[0].wire_packets, vec![vec![1]]);
            assert!(
                groups[0].drop_on_backpressure,
                "droppable packets keep their own retry policy"
            );
            assert_eq!(groups[1].target_key(), key_other_socket);
            assert_eq!(groups[1].wire_packets, vec![vec![2]]);
            assert!(groups[1].drop_on_backpressure);
            assert_eq!(groups[2].target_key(), key_a);
            assert_eq!(groups[2].wire_packets, vec![vec![3]]);
            assert!(
                groups[2].drop_on_backpressure,
                "same-target packets do not merge backward across an intervening target"
            );
            assert_eq!(groups[3].target_key(), key_a);
            assert_eq!(groups[3].wire_packets, vec![vec![4]]);
            assert!(
                !groups[3].drop_on_backpressure,
                "non-droppable control-shaped packets get their own retry policy"
            );
            assert_eq!(groups[4].target_key(), key_a);
            assert_eq!(groups[4].wire_packets, vec![vec![5]]);
            assert!(groups[4].drop_on_backpressure);
            assert_eq!(groups[5].target_key(), key_other_dest);
            assert_eq!(groups[5].wire_packets, vec![vec![6]]);
            assert!(groups[5].drop_on_backpressure);
            assert_eq!(
                selected_send_group_stats(&groups),
                (6, 6, 6),
                "send-group telemetry counts adjacent target/policy groups without merging backward"
            );
        });
    }

    #[test]
    fn selected_send_batch_capacity_tracks_worker_drain() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let dest: SocketAddr = "127.0.0.1:10039".parse().unwrap();
            let target = SelectedSendTarget::new(
                socket.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let same_target = SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let key = target.key();

            let mut groups = Vec::new();
            push_selected_send_batch_with_capacity(
                &mut groups,
                target,
                key,
                vec![1],
                true,
                true,
                48,
            );
            assert_eq!(groups.len(), 1);
            assert!(
                groups[0].wire_packet_capacity() >= 48,
                "hot single-target worker batches should not grow their packet vector one flush at a time"
            );

            push_selected_send_batch_with_capacity(
                &mut groups,
                same_target,
                key,
                vec![2],
                true,
                true,
                48,
            );
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].wire_packets, vec![vec![1], vec![2]]);
            assert!(
                groups[0].wire_packet_capacity() >= 48,
                "coalescing should keep the pre-sized worker-drain capacity"
            );
            assert_eq!(
                selected_send_group_stats(&groups),
                (1, 2, 0),
                "coalesced same-target groups report one multi-packet send group"
            );
        });
    }

    #[test]
    fn uniform_target_send_batch_splits_only_on_backpressure_policy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let dest: SocketAddr = "127.0.0.1:10040".parse().unwrap();
            let target = SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let key = target.key();

            let mut groups = Vec::new();
            push_uniform_target_send_batch_with_capacity(
                &mut groups,
                &target,
                key,
                vec![1],
                true,
                true,
                32,
            );
            push_uniform_target_send_batch_with_capacity(
                &mut groups,
                &target,
                key,
                vec![2],
                true,
                true,
                32,
            );
            push_uniform_target_send_batch_with_capacity(
                &mut groups,
                &target,
                key,
                vec![3],
                true,
                false,
                32,
            );
            push_uniform_target_send_batch_with_capacity(
                &mut groups,
                &target,
                key,
                vec![4],
                true,
                false,
                32,
            );
            push_uniform_target_send_batch_with_capacity(
                &mut groups,
                &target,
                key,
                vec![5],
                true,
                true,
                32,
            );

            assert_eq!(groups.len(), 3);
            assert_eq!(groups[0].target_key(), key);
            assert_eq!(groups[0].wire_packets, vec![vec![1], vec![2]]);
            assert!(groups[0].drop_on_backpressure);
            assert_eq!(groups[1].wire_packets, vec![vec![3], vec![4]]);
            assert!(!groups[1].drop_on_backpressure);
            assert_eq!(groups[2].wire_packets, vec![vec![5]]);
            assert!(groups[2].drop_on_backpressure);
            assert_eq!(
                selected_send_group_stats(&groups),
                (3, 5, 1),
                "same-target container sends keep FIFO groups while preserving retry policy"
            );
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_send_batch_attempt_owns_cursor_and_backpressure_policy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let dest: SocketAddr = "127.0.0.1:10031".parse().unwrap();

            let target = SelectedSendTarget::new(
                socket.clone(),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let target_key = target.key();
            let mut batch = SelectedSendBatch::new(target, target_key, vec![1], true, true);
            batch.push(vec![2], true, true);

            let mut attempt = LinuxSendBatchAttempt::from_batch(batch);
            assert_eq!(attempt.target_key(), target_key);
            assert_eq!(attempt.remaining_packets(), &[vec![1], vec![2]]);
            attempt.mark_sent(1);
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

            let target = SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest,
            );
            let retry_target_key = target.key();
            let mut retry_batch =
                SelectedSendBatch::new(target, retry_target_key, vec![3], true, false);
            retry_batch.push(vec![4], true, false);
            let mut retry_attempt = LinuxSendBatchAttempt::from_batch(retry_batch);
            assert_eq!(
                retry_attempt.handle_backpressure_request(true, &err),
                SendBackpressureDecision::Retry
            );
            assert_eq!(
                retry_attempt.remaining_packets(),
                &[vec![3], vec![4]],
                "non-droppable send batches must not advance on a drop request"
            );
        });
    }
}
