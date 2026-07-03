    #[test]
    fn pending_rekey_tiebreak_keeps_local_initiator_only_when_smaller() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        entry.set_pending_session(make_xk_session(&local, &peer));

        assert!(pending_rekey_wins_tiebreak(
            &node_addr(0x01),
            &node_addr(0x02),
            &entry
        ));
        assert!(!pending_rekey_wins_tiebreak(
            &node_addr(0x02),
            &node_addr(0x01),
            &entry
        ));
    }

    #[test]
    fn pending_rekey_tiebreak_does_not_keep_responder_pending() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let rekey = HandshakeState::new_xk_responder(local.keypair());
        entry.set_rekey_state(rekey, false);
        entry.set_pending_session(make_xk_session(&peer, &local));

        assert!(!pending_rekey_wins_tiebreak(
            &node_addr(0x01),
            &node_addr(0x02),
            &entry
        ));
    }

    #[test]
    fn duplicate_rekey_responder_ack_only_for_responder_in_progress() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let ack_payload = vec![0x42, 0x43];
        let rekey = HandshakeState::new_xk_responder(local.keypair());
        entry.set_rekey_state(rekey, false);
        entry.set_handshake_payload(ack_payload.clone(), 2000);

        assert_eq!(
            duplicate_rekey_responder_ack(&entry),
            Some(ack_payload),
            "a rekey responder awaiting msg3 should replay its SessionAck"
        );

        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        assert!(
            duplicate_rekey_responder_ack(&entry).is_none(),
            "local rekey initiators still use the dual-initiation tiebreak"
        );
    }

    #[test]
    fn decrypt_failure_recovery_rekey_requires_threshold_and_no_pending_rekey() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let can_recover = |entry: &SessionEntry| {
            entry.is_established()
                && !entry.has_rekey_in_progress()
                && entry.pending_new_session().is_none()
        };

        assert!(!should_start_decrypt_failure_rekey(
            can_recover(&entry),
            DECRYPT_FAILURE_RECOVERY_THRESHOLD - 1,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS)
        ));
        assert!(should_start_decrypt_failure_rekey(
            can_recover(&entry),
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS)
        ));

        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        assert!(!should_start_decrypt_failure_rekey(
            false,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS)
        ));
        entry.abandon_rekey();

        entry.set_pending_session(make_xk_session(&local, &peer));
        assert!(!should_start_decrypt_failure_rekey(
            false,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS)
        ));
    }

    #[test]
    fn decrypt_failure_recovery_rekey_waits_for_quiet_session() {
        assert!(!should_start_decrypt_failure_rekey(
            true,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS - 1),
        ));
        assert!(should_start_decrypt_failure_rekey(
            true,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS),
        ));
        assert!(!should_start_decrypt_failure_rekey(
            true,
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            None,
        ));
    }

    #[test]
    fn recovery_rekey_uses_old_session_until_cutover_and_new_session_after() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let aad = b"fsp-test-aad";

        let (mut old_sender, old_receiver) = make_xk_session_pair(&peer, &local);
        let (mut new_sender, new_receiver) = make_xk_session_pair(&peer, &local);
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(old_receiver),
            1000,
            false,
        );

        // Recovery starts as an in-place rekey. The old session must remain
        // current and usable while the replacement XK handshake is in flight.
        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        let (counter, ciphertext) =
            encrypt_frame(&mut old_sender, b"old packet while rekey pending", aad);
        assert_eq!(
            decrypt_current(&mut entry, &ciphertext, counter, aad).unwrap(),
            b"old packet while rekey pending"
        );

        // Once the new session is ready but before K-bit cutover, traffic
        // still uses the old session.
        entry.set_pending_session(new_receiver);
        let (counter, ciphertext) =
            encrypt_frame(&mut old_sender, b"old packet before cutover", aad);
        assert_eq!(
            decrypt_current(&mut entry, &ciphertext, counter, aad).unwrap(),
            b"old packet before cutover"
        );

        // After cutover, SessionEntry promotes only the new session. dataplane owns
        // stale-epoch drain handling, so registry state no longer retains the
        // old NoiseSession for decrypt fallback.
        assert!(entry.cutover_to_new_session(2000));
        let (old_counter, old_ciphertext) =
            encrypt_frame(&mut old_sender, b"old packet after cutover", aad);
        assert!(decrypt_current(&mut entry, &old_ciphertext, old_counter, aad).is_err());

        let (new_counter, new_ciphertext) =
            encrypt_frame(&mut new_sender, b"new packet after cutover", aad);
        assert_eq!(
            decrypt_current(&mut entry, &new_ciphertext, new_counter, aad).unwrap(),
            b"new packet after cutover"
        );
    }
