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
        let (return_tx, mut return_rx) = decrypt_worker_return_channels_with_caps(4, 4);
        shard.pool.return_tx = return_tx.clone();
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
        match return_rx
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
            DecryptWorkerEvent::AuthenticatedLink(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::AuthenticatedLinkBatch(_) => {
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
                return_rx
                    .priority
                    .try_recv()
                    .expect("authenticated link return"),
                DecryptWorkerEvent::AuthenticatedLink(_)
            ),
            "valid packet must return as an authenticated link after FMP decrypt"
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
            return_rx.priority.is_empty(),
            "replayed counter must be dropped before plaintext or failure events"
        );
        assert!(
            return_rx.authenticated_bulk.is_empty(),
            "replayed counter must not reach the bulk completion lane"
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
        let (return_tx, mut return_rx) = decrypt_worker_return_channels_with_caps(4, 4);
        shard.pool.return_tx = return_tx.clone();
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

        match return_rx
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
            DecryptWorkerEvent::AuthenticatedLink(_)
            | DecryptWorkerEvent::AuthenticatedLinkBatch(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
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
            return_rx.authenticated_bulk.try_recv().is_err(),
            "timestamp-only receive must not consume the bulk completion lane"
        );
        assert_eq!(
            shard.fmp_replay_highest(session_key).unwrap(),
            counter,
            "successful timestamp-only AEAD must advance the worker-owned replay window"
        );
    }

    #[test]
    fn owned_session_state_open_fmp_accepts_replay_only_after_aead_success() {
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
        assert_eq!(invalid_precheck.replay_highest, 0);
        assert!(
            state.fmp_replay.check(counter),
            "precheck must not advance the replay window before AEAD succeeds"
        );
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
        assert!(
            state.accept_prechecked_fmp_replay(valid_precheck),
            "successful AEAD should accept the prechecked counter"
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
    fn fmp_owner_retire_accepts_replay_only_after_open_completion() {
        let key_bytes = [0x64u8; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let counter = 33;
        let flags = crate::node::wire::FLAG_SP;
        let mut state =
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer());

        let (invalid_packet, invalid_header) = invalid_fmp_test_packet(flags);
        let invalid_reservation = state
            .reserve_fmp_open(DecryptWorkerLane::Priority, counter)
            .expect("fresh counter should reserve an FMP owner ticket");
        let mut opener = FmpAeadOpener;
        let invalid_completion = FmpAeadCompletion::new(
            invalid_reservation,
            opener.execute(state.fmp_open_work(
                invalid_reservation,
                invalid_packet.into(),
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                invalid_header,
            )),
        );
        let mut failure = None;
        assert_eq!(
            state
                .complete_fmp_aead_completion(invalid_completion, |ready| failure = Some(ready))
                .expect("invalid FMP completion should retire"),
            1
        );
        assert!(matches!(
            failure,
            Some(FmpReadyCompletion::DecryptFailure {
                fmp_counter,
                fmp_replay_highest: 0,
            }) if fmp_counter == counter
        ));
        assert!(
            state.fmp_replay.check(counter),
            "failed AEAD completion must not consume the owner replay window"
        );

        let (valid_packet, valid_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        let valid_reservation = state
            .reserve_fmp_open(DecryptWorkerLane::Priority, counter)
            .expect("failed AEAD must leave the counter available");
        let valid_completion = FmpAeadCompletion::new(
            valid_reservation,
            opener.execute(state.fmp_open_work(
                valid_reservation,
                valid_packet.into(),
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                valid_header,
            )),
        );
        let mut opened_len = None;
        assert_eq!(
            state
                .complete_fmp_aead_completion(valid_completion, |ready| {
                    if let FmpReadyCompletion::Opened(opened) = ready {
                        opened_len = Some(opened.plaintext_len);
                    }
                })
                .expect("valid FMP completion should retire"),
            1
        );
        assert_eq!(opened_len, Some(5));
        assert_eq!(
            state.fmp_replay.highest(),
            counter,
            "successful owner-retired open must accept replay"
        );
    }

    #[test]
    fn fmp_owner_retire_holds_later_crypto_completion_until_gap_arrives() {
        let key_bytes = [0x65u8; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let flags = crate::node::wire::FLAG_SP;
        let mut state =
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer());
        let mut opener = FmpAeadOpener;

        let (first_packet, first_header) = sealed_fmp_test_packet(&seal_cipher, 41, flags);
        let first_reservation = state
            .reserve_fmp_open(DecryptWorkerLane::Bulk, 41)
            .expect("first FMP ticket");
        let first_completion = FmpAeadCompletion::new(
            first_reservation,
            opener.execute(state.fmp_open_work(
                first_reservation,
                first_packet.into(),
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                41,
                flags,
                first_header,
            )),
        );

        let (second_packet, second_header) = sealed_fmp_test_packet(&seal_cipher, 42, flags);
        let second_reservation = state
            .reserve_fmp_open(DecryptWorkerLane::Bulk, 42)
            .expect("second FMP ticket");
        let second_completion = FmpAeadCompletion::new(
            second_reservation,
            opener.execute(state.fmp_open_work(
                second_reservation,
                second_packet.into(),
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                42,
                flags,
                second_header,
            )),
        );

        let mut ready = 0;
        assert_eq!(
            state
                .complete_fmp_aead_completion(second_completion, |_| ready += 1)
                .expect("second completion should be held"),
            0
        );
        assert_eq!(ready, 0);
        assert_eq!(
            state.fmp_replay.highest(),
            0,
            "later FMP completion must not accept replay before the owner gap retires"
        );

        assert_eq!(
            state
                .complete_fmp_aead_completion(first_completion, |_| ready += 1)
                .expect("first completion should release both packets"),
            2
        );
        assert_eq!(ready, 2);
        assert_eq!(
            state.fmp_replay.highest(),
            42,
            "owner retire should accept ready FMP completions in receive order"
        );
    }

    #[test]
    fn fmp_replay_precheck_keeps_counter_available_until_accept() {
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
        assert!(
            state.fmp_replay.check(counter),
            "failed AEAD must leave the prechecked counter available for a valid packet"
        );
        let retry_precheck = state
            .precheck_fmp_replay(counter)
            .expect("failed AEAD must leave the counter available for a valid retry");

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
        assert!(
            state.accept_prechecked_fmp_replay(retry_precheck),
            "successful retry must consume replay after AEAD opens"
        );
        assert_eq!(state.fmp_replay.highest(), counter);
        assert!(
            !state.fmp_replay.check(counter),
            "accepting replay after AEAD makes the counter a replay"
        );
        assert_eq!(precheck.replay_highest, 0);
    }

    #[test]
    fn fmp_accept_prechecked_duplicate_counter_drops_and_counts() {
        crate::perf_profile::force_event_counters_for_test();
        let prechecked_before = crate::perf_profile::event_count_for_test(
            crate::perf_profile::Event::FmpAeadCompletionReplayDroppedPrechecked,
        );
        let duplicate_before = crate::perf_profile::event_count_for_test(
            crate::perf_profile::Event::FmpAeadCompletionReplayDroppedDuplicate,
        );
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
            .expect("a stale precheck can exist before the first accept");
        assert!(
            state.accept_prechecked_fmp_replay(first_precheck),
            "first prechecked counter should be accepted"
        );
        assert_eq!(state.fmp_replay.highest(), counter);
        assert_eq!(
            state.accept_prechecked_fmp_replay(duplicate_precheck),
            false,
            "stale duplicate precheck must not be accepted a second time"
        );
        assert!(
            crate::perf_profile::event_count_for_test(
                crate::perf_profile::Event::FmpAeadCompletionReplayDroppedPrechecked,
            ) > prechecked_before,
            "stale-precheck duplicate drop should retain the prechecked classification"
        );
        assert!(
            crate::perf_profile::event_count_for_test(
                crate::perf_profile::Event::FmpAeadCompletionReplayDroppedDuplicate,
            ) > duplicate_before,
            "stale-precheck duplicate drop should record the duplicate reason"
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
    fn worker_preserves_fmp_flags_through_authenticated_link() {
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

        let (return_tx, mut return_rx) = decrypt_worker_return_channels_with_caps(1, 1);
        shard.pool.return_tx = return_tx.clone();

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

        let event = return_rx
            .priority
            .try_recv()
            .expect("authenticated link delivered");
        let link = match event {
            DecryptWorkerEvent::AuthenticatedLink(link) => link,
            DecryptWorkerEvent::DecryptFailure(_) => panic!("expected authenticated link event"),
            DecryptWorkerEvent::AuthenticatedLinkBatch(_) => {
                panic!("expected authenticated link event")
            }
            DecryptWorkerEvent::AuthenticatedFmpReceive(_) => {
                panic!("expected authenticated link event")
            }
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("expected authenticated link event")
            }
            DecryptWorkerEvent::AuthenticatedSessionBatch(_) => {
                panic!("expected authenticated link event")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("expected authenticated link event")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("expected authenticated link event")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("expected authenticated link event")
            }
            DecryptWorkerEvent::DirectSessionDataBatch(_) => {
                panic!("expected authenticated link event")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("expected authenticated link event")
            }
        };
        assert_eq!(
            link.source_peer, source_peer,
            "authenticated link must carry the worker-registered source peer"
        );
        assert_eq!(
            link.fmp_flags, flags_byte,
            "fmp_flags must round-trip from DecryptJob to DecryptAuthenticatedLink"
        );
        assert!(
            link.fmp_flags & crate::node::wire::FLAG_CE != 0,
            "FLAG_CE bit lost on worker path"
        );
        assert!(
            link.fmp_flags & crate::node::wire::FLAG_SP != 0,
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

        let (return_tx, mut return_rx) = decrypt_worker_return_channels_with_caps(1, 1);
        shard.pool.return_tx = return_tx.clone();
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

        let event = return_rx.priority.try_recv().expect("failure delivered");
        match event {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert_eq!(report.source_peer, source_peer);
                assert_eq!(report.fmp_counter, counter);
            }
            DecryptWorkerEvent::AuthenticatedLink(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::AuthenticatedLinkBatch(_) => {
                panic!("expected decrypt failure report")
            }
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
