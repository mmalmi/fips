    #[test]
    fn fresh_pending_rekey_outranks_unauthenticated_setup() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        entry.set_pending_session(make_xk_session(&local, &peer));
        entry.set_rekey_completed_ms(1_000);

        assert!(pending_rekey_outranks_setup(&entry, 1_999, 1_000));
        assert!(!pending_rekey_outranks_setup(&entry, 2_001, 1_000));
    }

    #[test]
    fn fresh_responder_pending_rekey_also_outranks_setup() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        let rekey = HandshakeState::new_xk_responder(local.keypair());
        entry.set_rekey_state(rekey, false);
        entry.set_pending_session(make_xk_session(&peer, &local));
        entry.set_rekey_completed_ms(1_000);

        assert!(pending_rekey_outranks_setup(&entry, 1_999, 1_000));
    }

    #[tokio::test]
    async fn forged_session_ack_preserves_the_initiating_entry() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut node = Node::with_identity(local, crate::config::Config::new()).expect("node");

        let mut initiator =
            HandshakeState::new_xk_initiator(node.identity.keypair(), peer.pubkey_full());
        initiator.set_local_epoch([1u8; 8]);
        let mut responder = HandshakeState::new_xk_responder(peer.keypair());
        responder.set_local_epoch([2u8; 8]);
        let msg1 = initiator.write_xk_message_1().unwrap();
        responder.read_xk_message_1(&msg1).unwrap();
        let genuine_msg2 = responder.write_xk_message_2().unwrap();

        node.sessions.install_initiating_session(
            peer_addr,
            peer.pubkey_full(),
            initiator,
            vec![0x11, 0x22],
            1_000,
            250,
        );
        let mut forged_msg2 = genuine_msg2;
        forged_msg2[XK_HANDSHAKE_MSG2_SIZE - 1] ^= 0x80;
        let ack = SessionAck::new(
            node.tree_state.my_coords().clone(),
            node.tree_state.my_coords().clone(),
        )
        .with_handshake(forged_msg2)
        .encode();

        node.handle_session_ack(
            &peer_addr,
            &peer_addr,
            &ack[FSP_COMMON_PREFIX_SIZE..],
        )
        .await;

        let entry = node
            .sessions
            .get(&peer_addr)
            .expect("forged ack must not remove the initiation");
        assert!(entry.is_initiating());
        assert_eq!(entry.created_at(), 1_000);
        assert_eq!(entry.handshake_payload(), Some([0x11, 0x22].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 1_250);
    }

    #[tokio::test]
    async fn rekey_key_mismatch_preserves_live_and_pending_epochs_without_mutation() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let attacker = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut node =
            Node::with_identity(local, crate::config::Config::new()).expect("node");
        let mut entry = established_entry(&node.identity, &peer);
        let original_hash = *entry.handshake_hash().expect("established hash");
        let original_pubkey = *entry.remote_pubkey();
        let original_identity = entry.remote_identity();

        entry.set_rekey_state(
            HandshakeState::new_xk_initiator(node.identity.keypair(), peer.pubkey_full()),
            true,
        );
        entry.set_pending_session(make_xk_session(&node.identity, &peer));
        entry.set_rekey_completed_ms(5_000);

        let mut attacker_handshake =
            HandshakeState::new_xk_initiator(attacker.keypair(), node.identity.pubkey_full());
        attacker_handshake.set_local_epoch([3u8; 8]);
        let mut responder = HandshakeState::new_xk_responder(node.identity.keypair());
        responder.set_local_epoch([4u8; 8]);
        let msg1 = attacker_handshake.write_xk_message_1().unwrap();
        responder.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder.write_xk_message_2().unwrap();
        attacker_handshake.read_xk_message_2(&msg2).unwrap();
        let msg3 = attacker_handshake.write_xk_message_3().unwrap();

        entry.set_rekey_state(responder, false);
        entry.set_handshake_payload(vec![0x44], 5_250);
        node.sessions.insert(peer_addr, entry);
        let wire = SessionMsg3::new(msg3).encode();
        node.handle_session_msg3(
            &peer_addr,
            &peer_addr,
            &wire[FSP_COMMON_PREFIX_SIZE..],
        )
        .await;

        let entry = node.sessions.get(&peer_addr).expect("live session retained");
        assert_eq!(entry.handshake_hash(), Some(&original_hash));
        assert_eq!(*entry.remote_pubkey(), original_pubkey);
        assert_eq!(entry.remote_identity(), original_identity);
        assert!(entry.pending_new_session().is_some());
        assert!(entry.pending_rekey_initiator());
        assert!(!entry.has_rekey_in_progress());
        assert_eq!(entry.handshake_payload(), None);
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
    fn decrypt_failure_recovery_rekey_requires_threshold_and_no_active_handshake() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);

        assert!(!should_start_decrypt_failure_rekey(
            session_can_recover_from_decrypt_failures(&entry, 10_000),
            DECRYPT_FAILURE_RECOVERY_THRESHOLD - 1,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS)
        ));
        assert!(should_start_decrypt_failure_rekey(
            session_can_recover_from_decrypt_failures(&entry, 10_000),
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS)
        ));

        let rekey = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        entry.set_rekey_state(rekey, true);
        assert!(!should_start_decrypt_failure_rekey(
            session_can_recover_from_decrypt_failures(&entry, 10_000),
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS)
        ));
        entry.abandon_rekey();

        entry.set_pending_session(make_xk_session(&local, &peer));
        entry.set_rekey_completed_ms(9_999);
        assert!(!session_can_recover_from_decrypt_failures(
            &entry, 10_000
        ));
        entry.set_rekey_completed_ms(1_000);
        assert!(session_can_recover_from_decrypt_failures(
            &entry, 10_000
        ));
        assert!(should_start_decrypt_failure_rekey(
            session_can_recover_from_decrypt_failures(&entry, 10_000),
            DECRYPT_FAILURE_RECOVERY_THRESHOLD,
            Some(DECRYPT_FAILURE_RECOVERY_QUIET_MS)
        ), "a stalled completed epoch must not permanently block recovery");
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
    fn authenticated_pending_epoch_cutover_supersedes_a_side_recovery_handshake() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        entry.set_rekey_state(
            HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full()),
            true,
        );
        entry.set_pending_session(make_xk_session(&local, &peer));
        entry.set_rekey_state(
            HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full()),
            true,
        );
        entry.set_handshake_payload(vec![0x55], 2_500);

        assert!(entry.cutover_to_authenticated_pending_epoch(2_000, true));
        assert!(entry.is_established());
        assert!(!entry.has_rekey_in_progress());
        assert!(entry.pending_new_session().is_none());
        assert!(entry.handshake_payload().is_none());
        assert!(entry.current_k_bit());
    }

    #[tokio::test]
    async fn persistent_decrypt_failures_evict_poisoned_session() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut node = Node::with_identity(local, crate::config::Config::new()).expect("node");
        node.sessions.insert(
            peer_addr,
            SessionEntry::new(
                peer_addr,
                peer.pubkey_full(),
                EndToEndState::Established(make_xk_session(&node.identity, &peer)),
                1,
                true,
            ),
        );
        assert!(
            node.sync_dataplane_fsp_owner_from_current_session(&peer_addr, 0),
            "fixture must install the production dataplane session owner"
        );

        for counter in 1..DECRYPT_FAILURE_EVICTION_THRESHOLD {
            assert!(
                node.handle_dataplane_fsp_decrypt_failure(peer_addr, u64::from(counter), false)
                    .await,
                "known poisoned session should consume reported decrypt failures"
            );
            assert!(
                node.sessions.get(&peer_addr).is_some(),
                "recovery gets a bounded chance before eviction"
            );
        }

        assert!(
            node.handle_dataplane_fsp_decrypt_failure(
                peer_addr,
                u64::from(DECRYPT_FAILURE_EVICTION_THRESHOLD),
                false,
            )
            .await
        );
        assert!(
            node.sessions.get(&peer_addr).is_none(),
            "a permanently poisoned session must not consume receive-loop capacity forever"
        );
        assert!(
            !node.dataplane_has_fsp_owner(&peer_addr),
            "eviction must remove the stale crypto owner"
        );
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
