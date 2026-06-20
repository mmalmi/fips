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
                fallback_tx.clone(),
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
                fallback_tx.clone(),
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
                fallback_tx,
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
                fallback_tx,
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
        let err = state
            .open_fmp_in_place(
                &mut invalid_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                &invalid_header,
            )
            .expect_err("invalid AEAD must not open");
        assert_eq!(
            err,
            FmpOpenError::Aead {
                fmp_replay_highest: 0
            }
        );
        assert_eq!(
            state.fmp_replay.highest(),
            0,
            "failed AEAD must not advance the owned replay window"
        );

        let (mut valid_packet, valid_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        let outcome = state
            .open_fmp_in_place(
                &mut valid_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                &valid_header,
            )
            .expect("valid AEAD must open");
        assert_eq!(outcome.plaintext_len, 5);
        assert_eq!(
            state.fmp_replay.highest(),
            counter,
            "successful AEAD must accept the counter in the same owner"
        );

        let (mut replay_packet, replay_header) =
            sealed_fmp_test_packet(&seal_cipher, counter, flags);
        let err = state
            .open_fmp_in_place(
                &mut replay_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                &replay_header,
            )
            .expect_err("replayed counter must be rejected before AEAD");
        assert_eq!(err, FmpOpenError::Replay);
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
        let err = state
            .open_fmp_in_place(
                &mut invalid_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                flags,
                &invalid_header,
            )
            .expect_err("failed AEAD must be reported without consuming replay");
        assert_eq!(
            err,
            FmpOpenError::Aead {
                fmp_replay_highest: 0
            }
        );
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
        state
            .accept_prechecked_fmp_replay(precheck)
            .expect("first ordered completion consumes replay");
        assert_eq!(state.fmp_replay.highest(), counter);
        assert!(
            !state.fmp_replay.check(counter),
            "ordered completion accept makes the counter a replay"
        );
        assert_eq!(
            state.accept_prechecked_fmp_replay(duplicate_precheck),
            Err(FmpOpenError::Replay),
            "ordered replay owner must re-check a prechecked counter at completion time"
        );
    }

    #[test]
    fn fmp_aead_helper_job_opens_packet_into_completion() {
        let key_bytes = [0x4a; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let session_key = test_session_key(1, 441);
        let counter = 44;
        let flags = crate::node::wire::FLAG_SP;
        let (packet_data, fmp_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let (completion_tx, _completion_rx) = bounded::<FmpAeadCompletionBatch>(1);
        let precheck = FmpReplayPrecheck {
            counter,
            replay_highest: 0,
        };
        let ticket = FmpReceiveTicket { sequence: 7 };

        let completion = FmpAeadHelperJob {
            session_key,
            receive_order_id: 42,
            ticket,
            replay: FmpReplayDecision::Prechecked(precheck),
            cipher: open_cipher.into(),
            fmp_header,
            opened: OpenedFmpJob {
                packet_data: packet_data.into(),
                lane: DecryptWorkerLane::Bulk,
                source_peer: test_source_peer(),
                transport_id: TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                local_node_addr: *test_source_peer().node_addr(),
                timestamp_ms: 1_000,
                packet_len: crate::node::wire::ESTABLISHED_HEADER_SIZE + 5 + 16,
                fmp_counter: counter,
                fmp_flags: flags,
                fmp_plaintext_offset: crate::node::wire::ESTABLISHED_HEADER_SIZE,
                fmp_plaintext_len: 0,
                fallback_tx,
            },
            completion_tx: Some(completion_tx),
            helper_queued_at: None,
        }
        .into_completion();

        assert_eq!(completion.session_key, session_key);
        assert_eq!(completion.receive_order_id, 42);
        assert_eq!(completion.ticket, ticket);
        match completion.result {
            FmpAeadCompletionResult::Opened {
                replay: got_replay,
                opened,
            } => {
                assert_eq!(got_replay, FmpReplayDecision::Prechecked(precheck));
                assert_eq!(opened.fmp_plaintext_len, 5);
                assert_eq!(
                    &opened.packet_data[opened.fmp_plaintext_offset
                        ..opened.fmp_plaintext_offset + opened.fmp_plaintext_len],
                    &[0, 0, 0, 0, 0xAB]
                );
            }
            FmpAeadCompletionResult::AeadFailed(_) => {
                panic!("valid helper packet must open")
            }
        }
    }

    #[test]
    fn fmp_aead_completion_ignores_stale_receive_order() {
        let session_key = test_session_key(1, 442);
        let mut shard = test_shard();
        let stale_state = test_owned_session_state();
        let stale_receive_order_id = stale_state.fmp_receive_order_id();
        shard.register_session(0, session_key, stale_state);
        shard.register_session(0, session_key, test_owned_session_state());

        let (fallback_tx, fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let completion = FmpAeadCompletion {
            session_key,
            receive_order_id: stale_receive_order_id,
            ticket: FmpReceiveTicket { sequence: 0 },
            completed_at: None,
            result: FmpAeadCompletionResult::AeadFailed(dummy_fmp_aead_failure(fallback_tx, 45)),
        };

        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        shard.handle_fmp_aead_completion_msg(0, completion, &mut plaintext_batch);
        plaintext_batch.flush();

        assert!(
            fallback_rx.priority.is_empty(),
            "stale helper completions must not emit failure events for a replaced session"
        );
        assert!(
            fallback_rx.bulk.is_empty(),
            "stale helper completions must not emit plaintext for a replaced session"
        );
        assert_eq!(
            shard.fmp_replay_highest(session_key),
            Some(0),
            "stale helper completions must not mutate the replacement replay window"
        );
    }

    #[test]
    fn fmp_aead_failure_waits_for_receive_order_before_reporting() {
        let session_key = test_session_key(1, 445);
        let mut state = test_owned_session_state();
        let receive_order_id = state.fmp_receive_order_id();
        let first_ticket = state.issue_fmp_receive_ticket().expect("test ticket");
        let second_ticket = state.issue_fmp_receive_ticket().expect("test ticket");

        let mut shard = test_shard();
        shard.register_session(0, session_key, state);

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        let second_completion = FmpAeadCompletion {
            session_key,
            receive_order_id,
            ticket: second_ticket,
            completed_at: None,
            result: FmpAeadCompletionResult::AeadFailed(dummy_fmp_aead_failure(
                fallback_tx.clone(),
                102,
            )),
        };

        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        shard.handle_fmp_aead_completion_msg(0, second_completion, &mut plaintext_batch);
        plaintext_batch.flush();
        assert!(
            fallback_rx.priority.is_empty(),
            "later helper failure must not report before the missing earlier ticket"
        );

        let first_completion = FmpAeadCompletion {
            session_key,
            receive_order_id,
            ticket: first_ticket,
            completed_at: None,
            result: FmpAeadCompletionResult::AeadFailed(dummy_fmp_aead_failure(fallback_tx, 101)),
        };
        shard.handle_fmp_aead_completion_msg(0, first_completion, &mut plaintext_batch);
        plaintext_batch.flush();

        let first_report = match fallback_rx.priority.try_recv().expect("first failure report") {
            DecryptWorkerEvent::DecryptFailure(report) => report,
            _ => panic!("expected first decrypt failure report"),
        };
        let second_report = match fallback_rx.priority.try_recv().expect("second failure report") {
            DecryptWorkerEvent::DecryptFailure(report) => report,
            _ => panic!("expected second decrypt failure report"),
        };
        assert_eq!(first_report.fmp_counter, 101);
        assert_eq!(second_report.fmp_counter, 102);
        assert!(
            fallback_rx.priority.is_empty(),
            "only the two ordered failure reports should be emitted"
        );
    }

    #[test]
    fn fmp_aead_helper_window_wait_drains_oldest_completion() {
        let session_key = test_session_key(1, 443);
        let mut state = test_owned_session_state();
        let receive_order_id = state.fmp_receive_order_id();
        let receive_window = fmp_receive_window();
        let tickets = (0..receive_window)
            .map(|_| state.issue_fmp_receive_ticket().expect("test ticket"))
            .collect::<Vec<_>>();

        let mut shard = test_shard();
        let (helper_tx, _helper_rx) = bounded::<FmpAeadHelperJob>(1);
        shard.pool.fmp_aead_helpers = Some(Arc::new(FmpAeadHelperPool { tx: helper_tx }));
        shard.register_session(0, session_key, state);
        assert!(
            !shard.fmp_receive_order_window_available(session_key),
            "issuing one full receive-order window must stop further ticket issue"
        );

        let (_control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (completion_tx, completion_rx) = bounded::<FmpAeadCompletionBatch>(1);
        let (fallback_tx, fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        completion_tx
            .try_send(FmpAeadCompletionBatch::one(FmpAeadCompletion {
                session_key,
                receive_order_id,
                ticket: tickets[0],
                completed_at: None,
                result: FmpAeadCompletionResult::AeadFailed(dummy_fmp_aead_failure(
                    fallback_tx,
                    45,
                )),
            }))
            .expect("test completion lane has room");

        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        assert!(wait_for_fmp_receive_order_window(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &completion_rx,
            session_key,
            &mut plaintext_batch,
            &mut batch_stats,
        ));
        plaintext_batch.flush();

        assert!(
            shard.fmp_receive_order_window_available(session_key),
            "oldest helper completion must reopen the ordered receive window"
        );
        assert!(
            !fallback_rx.priority.is_empty(),
            "AEAD failures drained while waiting must remain observable"
        );
    }

    #[test]
    fn fmp_ordered_completion_buffers_out_of_order_crypto_results() {
        let key_bytes = [0x56u8; 32];
        let open_cipher = test_chacha_key(key_bytes);
        let mut state =
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer());

        let first_precheck = state
            .precheck_fmp_replay(20)
            .expect("first fresh counter should pass precheck");
        let first_ticket = state.issue_fmp_receive_ticket().expect("test ticket");
        let second_precheck = state
            .precheck_fmp_replay(21)
            .expect("second fresh counter should pass precheck");
        let second_ticket = state.issue_fmp_receive_ticket().expect("test ticket");

        let drain = state
            .complete_ordered_fmp_open(
                second_ticket,
                FmpOrderedCompletion::Opened {
                    replay: FmpReplayDecision::Prechecked(second_precheck),
                    value: dummy_opened_fmp_job(21),
                },
            )
            .expect("later completion should buffer behind missing first ticket");
        assert_eq!(drain, FmpOrderedDrain::default());
        assert_eq!(
            state.fmp_replay.highest(),
            0,
            "out-of-order completion must not advance replay until the gap closes"
        );

        let drain = state
            .complete_ordered_fmp_open(
                first_ticket,
                FmpOrderedCompletion::Opened {
                    replay: FmpReplayDecision::Prechecked(first_precheck),
                    value: dummy_opened_fmp_job(20),
                },
            )
            .expect("first completion should drain itself and the buffered second completion");
        assert_eq!(
            drain,
            FmpOrderedDrain {
                ready: 2,
                accepted: 2,
                aead_failures: 0,
                replay_drops: 0,
            }
        );
        assert_eq!(state.fmp_replay.highest(), 21);
    }

    #[test]
    fn fmp_ordered_completion_aead_failure_releases_later_completion() {
        let key_bytes = [0x57u8; 32];
        let open_cipher = test_chacha_key(key_bytes);
        let mut state =
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer());

        let failed_ticket = state.issue_fmp_receive_ticket().expect("test ticket");
        let later_precheck = state
            .precheck_fmp_replay(22)
            .expect("later fresh counter should pass precheck");
        let later_ticket = state.issue_fmp_receive_ticket().expect("test ticket");

        let drain = state
            .complete_ordered_fmp_open(
                later_ticket,
                FmpOrderedCompletion::Opened {
                    replay: FmpReplayDecision::Prechecked(later_precheck),
                    value: dummy_opened_fmp_job(22),
                },
            )
            .expect("later completion should wait behind the failed crypto ticket");
        assert_eq!(drain, FmpOrderedDrain::default());

        let drain = state
            .complete_ordered_fmp_open(
                failed_ticket,
                FmpOrderedCompletion::AeadFailed(dummy_fmp_aead_failure(
                    decrypt_worker_fallback_channels_with_caps(1, 1).0,
                    21,
                )),
            )
            .expect("AEAD failure should close the ordering gap without consuming replay");
        assert_eq!(
            drain,
            FmpOrderedDrain {
                ready: 2,
                accepted: 1,
                aead_failures: 1,
                replay_drops: 0,
            }
        );
        assert_eq!(
            state.fmp_replay.highest(),
            22,
            "later authenticated completion should drain after the failed ticket"
        );
    }

    #[test]
    fn fmp_ordered_completion_rechecks_duplicate_counter_at_drain() {
        let key_bytes = [0x58u8; 32];
        let open_cipher = test_chacha_key(key_bytes);
        let mut state =
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer());
        let counter = 23;

        let first_precheck = state
            .precheck_fmp_replay(counter)
            .expect("first duplicate candidate should pass before either completion drains");
        let first_ticket = state.issue_fmp_receive_ticket().expect("test ticket");
        let duplicate_precheck = state
            .precheck_fmp_replay(counter)
            .expect("duplicate can pass precheck while the first completion is pending");
        let duplicate_ticket = state.issue_fmp_receive_ticket().expect("test ticket");

        let drain = state
            .complete_ordered_fmp_open(
                duplicate_ticket,
                FmpOrderedCompletion::Opened {
                    replay: FmpReplayDecision::Prechecked(duplicate_precheck),
                    value: dummy_opened_fmp_job(230),
                },
            )
            .expect("duplicate completion should buffer behind the first ticket");
        assert_eq!(drain, FmpOrderedDrain::default());

        let drain = state
            .complete_ordered_fmp_open(
                first_ticket,
                FmpOrderedCompletion::Opened {
                    replay: FmpReplayDecision::Prechecked(first_precheck),
                    value: dummy_opened_fmp_job(23),
                },
            )
            .expect("first completion should accept and the duplicate should drain as replay");
        assert_eq!(
            drain,
            FmpOrderedDrain {
                ready: 2,
                accepted: 1,
                aead_failures: 0,
                replay_drops: 1,
            }
        );
        assert_eq!(state.fmp_replay.highest(), counter);
        assert!(
            !state.fmp_replay.check(counter),
            "ordered drain must leave the duplicate counter rejected"
        );
    }

    #[test]
    fn fmp_ordered_completion_drains_opened_values_in_receive_order() {
        let key_bytes = [0x59u8; 32];
        let open_cipher = test_chacha_key(key_bytes);
        let mut state =
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), test_source_peer());

        let first_precheck = state
            .precheck_fmp_replay(24)
            .expect("first fresh counter should pass precheck");
        let first_ticket = state.issue_fmp_receive_ticket().expect("test ticket");
        let second_precheck = state
            .precheck_fmp_replay(25)
            .expect("second fresh counter should pass precheck");
        let second_ticket = state.issue_fmp_receive_ticket().expect("test ticket");
        let mut opened = Vec::new();

        let drain = state
            .complete_ordered_fmp_open_with_value(
                second_ticket,
                FmpOrderedCompletion::Opened {
                    replay: FmpReplayDecision::Prechecked(second_precheck),
                    value: dummy_opened_fmp_job(250),
                },
                |ready| match ready {
                    FmpReadyCompletion::Opened(job) => opened.push(job.fmp_plaintext_len),
                    FmpReadyCompletion::AeadFailed(_) => {
                        panic!("test does not queue AEAD failures")
                    }
                },
            )
            .expect("second completion should buffer");
        assert_eq!(drain, FmpOrderedDrain::default());
        assert!(
            opened.is_empty(),
            "buffered completion value must not be delivered before the gap closes"
        );

        let drain = state
            .complete_ordered_fmp_open_with_value(
                first_ticket,
                FmpOrderedCompletion::Opened {
                    replay: FmpReplayDecision::Prechecked(first_precheck),
                    value: dummy_opened_fmp_job(240),
                },
                |ready| match ready {
                    FmpReadyCompletion::Opened(job) => opened.push(job.fmp_plaintext_len),
                    FmpReadyCompletion::AeadFailed(_) => {
                        panic!("test does not queue AEAD failures")
                    }
                },
            )
            .expect("first completion should drain both opened values");
        assert_eq!(
            drain,
            FmpOrderedDrain {
                ready: 2,
                accepted: 2,
                aead_failures: 0,
                replay_drops: 0,
            }
        );
        assert_eq!(
            opened,
            vec![240, 250],
            "opened values must be handed to owner-side dispatch in receive order"
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
            fallback_tx,
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
            fallback_tx,
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
