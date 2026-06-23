    #[test]
    fn decrypt_worker_accepts_fmp_replay_only_after_aead_success() {
        let key_bytes = [3u8; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let session_key = test_session_key(1, 79);
        let mut shard = test_shard();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer()),
        );
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        shard.pool.fallback_tx = fallback_tx.clone();
        let counter = 7;
        let flags = crate::node::wire::FLAG_CE | crate::node::wire::FLAG_SP;

        let (invalid_packet, invalid_header) = invalid_fmp_test_packet(flags);
        shard
            .handle_job(decrypt_job_for_test_packet(
                invalid_packet,
                invalid_header,
                session_key,
                counter,
                flags,
            ))
            .expect("invalid worker job should be handled");
        match fallback_rx
            .priority
            .try_recv()
            .expect("AEAD failure report")
        {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert_eq!(report.fmp_counter, counter);
                assert_eq!(
                    report.fmp_replay_highest, 0,
                    "failed AEAD must report the old replay high-water mark"
                );
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("invalid packet must not produce plaintext"),
            DecryptWorkerEvent::PlaintextBatch(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::AuthenticatedFmpReceive(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::AuthenticatedSessionBatch(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::DirectSessionDataBatch(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("invalid packet must fail FMP AEAD")
            }
        }
        assert_eq!(
            shard.fmp_replay_highest(session_key).unwrap(),
            0,
            "failed AEAD must not consume the worker-owned replay window"
        );

        let (valid_packet, valid_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        shard
            .handle_job(decrypt_job_for_test_packet(
                valid_packet,
                valid_header,
                session_key,
                counter,
                flags,
            ))
            .expect("valid worker job should be handled");
        assert!(
            matches!(
                fallback_rx.priority.try_recv().expect("plaintext fallback"),
                DecryptWorkerEvent::Plaintext(_)
            ),
            "valid packet must bounce plaintext after FMP decrypt"
        );
        assert_eq!(
            shard.fmp_replay_highest(session_key).unwrap(),
            counter,
            "successful AEAD must advance the worker-owned replay window"
        );

        let (replay_packet, replay_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        shard
            .handle_job(decrypt_job_for_test_packet(
                replay_packet,
                replay_header,
                session_key,
                counter,
                flags,
            ))
            .expect("replay worker job should be handled");
        assert!(
            fallback_rx.priority.is_empty(),
            "replayed counter must be dropped before plaintext or failure events"
        );
        assert!(
            fallback_rx.bulk.is_empty(),
            "replayed counter must not reach the bulk fallback lane"
        );
    }

    #[test]
    fn worker_emits_compact_authenticated_receive_for_timestamp_only_fmp() {
        let key_bytes = [7u8; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let session_key = test_session_key(1, 80);
        let mut shard = test_shard();
        let source_peer = test_source_peer();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), source_peer),
        );
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        shard.pool.fallback_tx = fallback_tx.clone();
        let counter = 11;
        let flags = crate::node::wire::FLAG_CE | crate::node::wire::FLAG_SP;
        let inner_timestamp_ms = 0x0102_0304_u32;
        let (packet, header) = sealed_fmp_test_packet_with_plaintext(
            &seal_cipher,
            counter,
            flags,
            &inner_timestamp_ms.to_le_bytes(),
        );

        shard
            .handle_job(decrypt_job_for_test_packet(
                packet,
                header,
                session_key,
                counter,
                flags,
            ))
            .expect("timestamp-only worker job should be handled");

        match fallback_rx
            .priority
            .try_recv()
            .expect("timestamp-only authenticated receive")
        {
            DecryptWorkerEvent::AuthenticatedFmpReceive(receive) => {
                assert_eq!(receive.fmp.source_peer, source_peer);
                assert_eq!(receive.fmp.fmp_counter, counter);
                assert_eq!(receive.fmp.inner_timestamp_ms, inner_timestamp_ms);
                assert_eq!(receive.fmp.fmp_flags, flags);
                assert_eq!(receive.lane, DecryptWorkerLane::Priority);
            }
            DecryptWorkerEvent::Plaintext(_) | DecryptWorkerEvent::PlaintextBatch(_) => {
                panic!("timestamp-only receive must not bounce plaintext bytes")
            }
            DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DirectSessionDataBatch(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("timestamp-only receive should be a compact bookkeeping event")
            }
        }
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "timestamp-only receive must not consume the fallback bulk lane"
        );
        assert_eq!(
            shard.fmp_replay_highest(session_key).unwrap(),
            counter,
            "successful timestamp-only AEAD must advance the worker-owned replay window"
        );
    }

    #[test]
    fn owned_session_state_open_fmp_owns_replay_acceptance() {
        let key_bytes = [4u8; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let counter = 9;
        let flags = crate::node::wire::FLAG_CE | crate::node::wire::FLAG_SP;
        let mut state =
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer());

        let (mut invalid_packet, invalid_header) = invalid_fmp_test_packet(flags);
        let invalid_precheck = state
            .precheck_fmp_replay(counter)
            .expect("fresh counter should pass before AEAD");
        assert!(
            OwnedSessionState::open_fmp_aead_in_place(
                &state.fmp_cipher,
                &mut invalid_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                &invalid_header,
            )
            .is_err(),
            "invalid AEAD must not open"
        );
        let invalid_ticket = state.issue_fmp_receive_ticket().expect("invalid ticket");
        let mut ready = Vec::new();
        let invalid_ready = state
            .complete_ordered_fmp_open(
                invalid_ticket,
                FmpOrderedCompletion::AeadFailed {
                    failure: dummy_fmp_decrypt_failure(counter),
                },
                |completion| ready.push(completion),
            )
            .expect("invalid AEAD completion should retire");
        assert_eq!(invalid_ready, 1);
        assert!(matches!(ready.last(), Some(FmpReadyCompletion::AeadFailed(_))));
        assert_eq!(invalid_precheck.replay_highest, 0);
        assert_eq!(
            state.fmp_replay.highest(),
            0,
            "failed AEAD must not advance the owned replay window"
        );

        let (mut valid_packet, valid_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        let valid_precheck = state
            .precheck_fmp_replay(counter)
            .expect("failed AEAD must leave the counter available");
        let outcome = OwnedSessionState::open_fmp_aead_in_place(
            &state.fmp_cipher,
            &mut valid_packet,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            counter,
            flags,
            &valid_header,
        )
        .expect("valid AEAD must open");
        let valid_ticket = state.issue_fmp_receive_ticket().expect("valid ticket");
        let valid_ready = state
            .complete_ordered_fmp_open(
                valid_ticket,
                FmpOrderedCompletion::Opened {
                    opened: dummy_opened_fmp_job(counter),
                    precheck: valid_precheck,
                },
                |completion| ready.push(completion),
            )
            .expect("valid AEAD completion should retire");
        assert_eq!(valid_ready, 1);
        assert!(
            matches!(ready.last(), Some(FmpReadyCompletion::Opened(_))),
            "valid AEAD should emit an opened ready completion"
        );
        assert_eq!(outcome.plaintext_len, 5);
        assert_eq!(
            state.fmp_replay.highest(),
            counter,
            "successful AEAD must accept the counter in the same owner"
        );

        let (mut replay_packet, replay_header) =
            sealed_fmp_test_packet(&seal_cipher, counter, flags);
        assert_eq!(
            state.precheck_fmp_replay(counter),
            Err(FmpOpenError::Replay),
            "replayed counter must be rejected before AEAD"
        );
        assert!(
            OwnedSessionState::open_fmp_aead_in_place(
                &state.fmp_cipher,
                &mut replay_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                &replay_header,
            )
            .is_ok(),
            "AEAD would authenticate, so replay ownership must reject before open work"
        );
        assert_eq!(
            state.fmp_replay.highest(),
            counter,
            "replay rejection must leave the owned replay window unchanged"
        );
    }

    #[test]
    fn fmp_replay_precheck_waits_for_ordered_crypto_completion() {
        let key_bytes = [0x55u8; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let counter = 19;
        let flags = crate::node::wire::FLAG_SP;
        let mut state =
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer());

        let precheck = state
            .precheck_fmp_replay(counter)
            .expect("fresh counter should pass the replay precheck");
        assert_eq!(precheck.counter, counter);
        assert_eq!(precheck.replay_highest, 0);
        assert_eq!(
            state.fmp_replay.highest(),
            0,
            "precheck must not advance the replay window before AEAD succeeds"
        );
        assert!(
            state.fmp_replay.check(counter),
            "prechecked counter is still admissible until ordered completion is accepted"
        );

        let (mut invalid_packet, invalid_header) = invalid_fmp_test_packet(flags);
        assert!(
            OwnedSessionState::open_fmp_aead_in_place(
                &state.fmp_cipher,
                &mut invalid_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                &invalid_header,
            )
            .is_err(),
            "failed AEAD must be reported without consuming replay"
        );
        let failed_ticket = state.issue_fmp_receive_ticket().expect("failed AEAD ticket");
        let mut ready = Vec::new();
        let failed_ready = state
            .complete_ordered_fmp_open(
                failed_ticket,
                FmpOrderedCompletion::AeadFailed {
                    failure: dummy_fmp_decrypt_failure(counter),
                },
                |completion| ready.push(completion),
            )
            .expect("failed AEAD completion should retire");
        assert_eq!(failed_ready, 1);
        assert!(matches!(ready.last(), Some(FmpReadyCompletion::AeadFailed(_))));
        assert!(
            state.fmp_replay.check(counter),
            "failed AEAD must leave the prechecked counter available for a valid packet"
        );
        let duplicate_precheck = state
            .precheck_fmp_replay(counter)
            .expect("a duplicate can pass precheck while the first completion is still pending");

        let (mut valid_packet, valid_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        OwnedSessionState::open_fmp_aead_in_place(
            &state.fmp_cipher,
            &mut valid_packet,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            counter,
            flags,
            &valid_header,
        )
        .expect("worker-side AEAD should authenticate independently");
        let success_ticket = state
            .issue_fmp_receive_ticket()
            .expect("successful AEAD ticket");
        state
            .complete_ordered_fmp_open(
                success_ticket,
                FmpOrderedCompletion::Opened {
                    opened: dummy_opened_fmp_job(counter),
                    precheck,
                },
                |completion| ready.push(completion),
            )
            .expect("first ordered completion consumes replay");
        assert_eq!(state.fmp_replay.highest(), counter);
        assert!(
            !state.fmp_replay.check(counter),
            "ordered completion accept makes the counter a replay"
        );
        let duplicate_ticket = state.issue_fmp_receive_ticket().expect("duplicate ticket");
        let ready_before_duplicate = ready.len();
        let duplicate_ready = state
            .complete_ordered_fmp_open(
                duplicate_ticket,
                FmpOrderedCompletion::Opened {
                    opened: dummy_opened_fmp_job(counter),
                    precheck: duplicate_precheck,
                },
                |completion| ready.push(completion),
            )
            .expect("duplicate completion should retire as replay drop");
        assert_eq!(duplicate_ready, 1);
        assert_eq!(
            ready.len(),
            ready_before_duplicate,
            "duplicate ordered completion must not emit a ready packet"
        );
    }

    #[test]
    fn fmp_ordered_completion_buffers_later_ready_until_missing_ticket() {
        let mut state = OwnedSessionState::new(
            test_chacha_key([0x61; 32]),
            ReplayWindow::new(),
            test_source_peer(),
        );
        let tickets = [
            state.issue_fmp_receive_ticket().expect("ticket 0"),
            state.issue_fmp_receive_ticket().expect("ticket 1"),
            state.issue_fmp_receive_ticket().expect("ticket 2"),
        ];
        let mut ready = Vec::new();

        let later = state
            .complete_ordered_fmp_open(
                tickets[1],
                FmpOrderedCompletion::AeadFailed {
                    failure: dummy_fmp_decrypt_failure(2),
                },
                |completion| ready.push(completion),
            )
            .expect("later completion should fit receive order");
        assert_eq!(later, 0);
        assert!(
            ready.is_empty(),
            "later completion must wait for the missing ticket"
        );

        let drain = state
            .complete_ordered_fmp_open(
                tickets[0],
                FmpOrderedCompletion::AeadFailed {
                    failure: dummy_fmp_decrypt_failure(1),
                },
                |completion| ready.push(completion),
            )
            .expect("oldest completion should drain itself and buffered later completion");
        assert_eq!(drain, 2);
        assert_eq!(ready.len(), 2);
        match (&ready[0], &ready[1]) {
            (
                FmpReadyCompletion::AeadFailed(first),
                FmpReadyCompletion::AeadFailed(second),
            ) => {
                assert_eq!(first.fmp_counter, 1);
                assert_eq!(second.fmp_counter, 2);
            }
            _ => panic!("expected ordered FMP failure completions"),
        }

        let drain = state
            .complete_ordered_fmp_open(
                tickets[2],
                FmpOrderedCompletion::AeadFailed {
                    failure: dummy_fmp_decrypt_failure(3),
                },
                |completion| ready.push(completion),
            )
            .expect("third completion should drain after the first two");
        assert_eq!(drain, 1);
        assert_eq!(ready.len(), 3);
    }

    #[test]
    fn fmp_ordered_completion_rechecks_duplicate_counter_at_retire() {
        let mut state = OwnedSessionState::new(
            test_chacha_key([0x62; 32]),
            ReplayWindow::new(),
            test_source_peer(),
        );
        let counter = 37;
        let first_precheck = state
            .precheck_fmp_replay(counter)
            .expect("fresh counter should pass precheck");
        let duplicate_precheck = state
            .precheck_fmp_replay(counter)
            .expect("duplicate can precheck before the first completion retires");
        let first_ticket = state.issue_fmp_receive_ticket().expect("ticket 0");
        let duplicate_ticket = state.issue_fmp_receive_ticket().expect("ticket 1");
        let mut ready = Vec::new();

        let first = state
            .complete_ordered_fmp_open(
                first_ticket,
                FmpOrderedCompletion::Opened {
                    opened: dummy_opened_fmp_job(counter),
                    precheck: first_precheck,
                },
                |completion| ready.push(completion),
            )
            .expect("first completion should retire");
        assert_eq!(first, 1);
        assert_eq!(state.fmp_replay.highest(), counter);
        assert_eq!(ready.len(), 1);

        let duplicate = state
            .complete_ordered_fmp_open(
                duplicate_ticket,
                FmpOrderedCompletion::Opened {
                    opened: dummy_opened_fmp_job(counter),
                    precheck: duplicate_precheck,
                },
                |completion| ready.push(completion),
            )
            .expect("duplicate completion should fit receive order");
        assert_eq!(duplicate, 1);
        assert_eq!(
            ready.len(),
            1,
            "duplicate counter must not emit a second ready packet"
        );
    }

    #[test]
    fn decrypt_worker_shard_owns_register_and_unregister_state() {
        let session_key = test_session_key(2, 80);
        let mut shard = test_shard();

        assert!(
            !shard.contains_session(session_key),
            "new shard starts without session state"
        );
        shard.handle_msg(
            0,
            WorkerMsg::RegisterSession {
                session_key,
                state: test_owned_session_state(),
            },
        );
        assert!(
            shard.contains_session(session_key),
            "registration must populate shard-owned state"
        );

        shard.handle_msg(0, WorkerMsg::UnregisterSession { session_key });
        assert!(
            !shard.contains_session(session_key),
            "unregister must remove shard-owned state"
        );
    }

    /// `DecryptJob.fmp_flags` must survive the worker bounce as
    /// `DecryptFallback.fmp_flags`. Pre-fix the worker hardcoded
    /// `fmp_flags: 0`, dropping CE / SP on every packet handled by
    /// the production worker path (i.e. every bulk-data packet).
    /// Loss of CE wrecks ECN propagation; loss of SP wrecks
    /// spin-bit RTT observation.
    ///
    /// Drives the worker's `handle_job` directly: build an FMP wire
    /// packet sealed with a known cipher, ship a `DecryptJob` with
    /// non-zero flags through, observe the resulting `DecryptFallback`.
    #[test]
    fn worker_preserves_fmp_flags_through_fallback() {
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        // Both the sealing cipher (for building the test packet) and
        // the worker's owning cipher are clones of the same key.
        let seal_cipher = LessSafeKey::new(unbound);
        let unbound2 = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let open_cipher = LessSafeKey::new(unbound2);

        let counter: u64 = 7;
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        // Build a wire packet `[16-byte header][4-byte inner ts][1 byte link msg]`
        // with capacity for the trailing AEAD tag. Header bytes
        // double as AAD and as the on-wire prefix.
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        // Header: fill the flags byte (the second byte) with both
        // FLAG_CE and FLAG_SP set; the rest is uninterpreted by the
        // worker (it just AADs the whole 16 bytes).
        let flags_byte = crate::node::wire::FLAG_CE | crate::node::wire::FLAG_SP;
        let mut header = [0u8; HDR];
        header[1] = flags_byte;
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]); // inner ts placeholder
        wire.push(0xAB); // a single byte of "link message" payload

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
        let (hdr_slice, payload_slice) = wire.split_at_mut(HDR);
        let tag = seal_cipher
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(&*hdr_slice), payload_slice)
            .unwrap();
        wire.extend_from_slice(tag.as_ref());

        // Owning state held by the worker for this session.
        let session_key = test_session_key(1, 99);
        let mut shard = test_shard();
        let source_peer = test_source_peer();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), source_peer),
        );

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        shard.pool.fallback_tx = fallback_tx.clone();

        let job = DecryptJob::new(
            wire,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *source_peer.node_addr(),
            1_000,
            counter,
            flags_byte,
            header,
            HDR,
        );

        shard.handle_job(job).expect("worker job handled");

        let event = fallback_rx.priority.try_recv().expect("fallback delivered");
        let fallback = match event {
            DecryptWorkerEvent::Plaintext(fallback) => fallback,
            DecryptWorkerEvent::DecryptFailure(_) => panic!("expected plaintext fallback event"),
            DecryptWorkerEvent::PlaintextBatch(_) => panic!("expected plaintext fallback event"),
            DecryptWorkerEvent::AuthenticatedFmpReceive(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::AuthenticatedSessionBatch(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::DirectSessionDataBatch(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("expected plaintext fallback event")
            }
        };
        assert_eq!(
            fallback.source_peer, source_peer,
            "plaintext fallback must carry the worker-registered source peer"
        );
        assert_eq!(
            fallback.fmp_flags, flags_byte,
            "fmp_flags must round-trip from DecryptJob to DecryptFallback"
        );
        assert!(
            fallback.fmp_flags & crate::node::wire::FLAG_CE != 0,
            "FLAG_CE bit lost on worker path"
        );
        assert!(
            fallback.fmp_flags & crate::node::wire::FLAG_SP != 0,
            "FLAG_SP bit lost on worker path"
        );
    }

    #[test]
    fn worker_reports_fmp_aead_failure_to_rx_loop() {
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let open_cipher = LessSafeKey::new(unbound);

        let counter: u64 = 11;
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let header = [0u8; HDR];
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(0xAB);
        wire.extend_from_slice(&[0u8; 16]); // invalid AEAD tag

        let session_key = test_session_key(1, 77);
        let mut shard = test_shard();
        let source_peer = test_source_peer();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), source_peer),
        );

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        shard.pool.fallback_tx = fallback_tx.clone();
        let job = DecryptJob::new(
            wire,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *source_peer.node_addr(),
            1_000,
            counter,
            0,
            header,
            HDR,
        );

        shard.handle_job(job).expect("worker job handled");

        let event = fallback_rx.priority.try_recv().expect("failure delivered");
        match event {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert_eq!(report.source_peer, source_peer);
                assert_eq!(report.fmp_counter, counter);
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("expected decrypt failure report"),
            DecryptWorkerEvent::PlaintextBatch(_) => panic!("expected decrypt failure report"),
            DecryptWorkerEvent::AuthenticatedFmpReceive(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::AuthenticatedSessionBatch(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::DirectSessionDataBatch(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => panic!("expected decrypt failure report"),
        }
    }

    fn dummy_fmp_decrypt_failure(counter: u64) -> DecryptFailureReport {
        DecryptFailureReport {
            source_peer: test_source_peer(),
            fmp_counter: counter,
            fmp_replay_highest: counter.saturating_sub(1),
            trace_enqueued_at: None,
        }
    }

    fn dummy_opened_fmp_job(counter: u64) -> OpenedFmpJob {
        let source_peer = test_source_peer();
        let mut packet_data =
            vec![0u8; crate::node::wire::ESTABLISHED_HEADER_SIZE + std::mem::size_of::<u32>()];
        let timestamp = (counter as u32).to_le_bytes();
        packet_data[crate::node::wire::ESTABLISHED_HEADER_SIZE..].copy_from_slice(&timestamp);
        OpenedFmpJob {
            packet_data: packet_data.into(),
            source_peer,
            transport_id: TransportId::new(1),
            remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            local_node_addr: *source_peer.node_addr(),
            timestamp_ms: counter,
            packet_len: crate::node::wire::ESTABLISHED_HEADER_SIZE
                + std::mem::size_of::<u32>(),
            fmp_counter: counter,
            fmp_flags: 0,
            fmp_plaintext_offset: crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fmp_plaintext_len: std::mem::size_of::<u32>(),
        }
    }
