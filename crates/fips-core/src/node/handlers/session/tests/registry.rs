    use super::*;
    use crate::Identity;
    use crate::noise::{NoiseError, NoiseSession};

    fn node_addr(byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        NodeAddr::from_bytes(bytes)
    }

    fn make_xk_session_pair(
        initiator: &Identity,
        responder: &Identity,
    ) -> (NoiseSession, NoiseSession) {
        let mut initiator_hs =
            HandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
        let mut responder_hs = HandshakeState::new_xk_responder(responder.keypair());
        initiator_hs.set_local_epoch([1u8; 8]);
        responder_hs.set_local_epoch([2u8; 8]);

        let msg1 = initiator_hs.write_xk_message_1().unwrap();
        responder_hs.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder_hs.write_xk_message_2().unwrap();
        initiator_hs.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator_hs.write_xk_message_3().unwrap();
        responder_hs.read_xk_message_3(&msg3).unwrap();

        (
            initiator_hs.into_session().unwrap(),
            responder_hs.into_session().unwrap(),
        )
    }

    fn make_xk_session(initiator: &Identity, responder: &Identity) -> NoiseSession {
        make_xk_session_pair(initiator, responder).0
    }

    fn encrypt_frame(session: &mut NoiseSession, plaintext: &[u8], aad: &[u8]) -> (u64, Vec<u8>) {
        let counter = session.current_send_counter();
        let ciphertext = session.encrypt_with_aad(plaintext, aad).unwrap();
        (counter, ciphertext)
    }

    fn decrypt_current(
        entry: &mut SessionEntry,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        match entry.take_state() {
            Some(EndToEndState::Established(mut session)) => {
                let result = session.decrypt_with_replay_check_and_aad(ciphertext, counter, aad);
                entry.set_state(EndToEndState::Established(session));
                result
            }
            Some(state) => {
                entry.set_state(state);
                unreachable!("test entry is established")
            }
            None => unreachable!("test entry state is present"),
        }
    }

    fn established_entry(local: &Identity, peer: &Identity) -> SessionEntry {
        let session = make_xk_session(local, peer);
        SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(session),
            1000,
            true,
        )
    }

    fn initiating_entry(local: &Identity, peer: &Identity) -> SessionEntry {
        let mut handshake = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        handshake.set_local_epoch([1u8; 8]);
        SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
        )
    }

    #[test]
    fn session_registry_owns_session_initiation_skip_policy() {
        let local = Identity::generate();
        let established_peer = Identity::generate();
        let initiating_peer = Identity::generate();
        let established_addr = *established_peer.node_addr();
        let initiating_addr = *initiating_peer.node_addr();
        let missing_addr = node_addr(0x99);
        let mut sessions = crate::node::SessionRegistry::default();
        assert!(
            sessions
                .insert(established_addr, established_entry(&local, &established_peer))
                .is_none()
        );
        assert!(
            sessions
                .insert(initiating_addr, initiating_entry(&local, &initiating_peer))
                .is_none()
        );

        assert!(sessions.should_skip_session_initiation(&established_addr));
        assert!(sessions.should_skip_session_initiation(&initiating_addr));
        assert!(!sessions.should_skip_session_initiation(&missing_addr));
    }

    #[test]
    fn session_registry_owns_handshake_session_installation() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();

        let mut initiating_handshake =
            HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        initiating_handshake.set_local_epoch([1u8; 8]);
        assert!(
            sessions
                .install_initiating_session(
                    peer_addr,
                    peer.pubkey_full(),
                    initiating_handshake,
                    vec![0x11, 0x22],
                    1_000,
                    250,
                )
                .is_none()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("initiating session should be installed");
        assert!(entry.is_initiating());
        assert!(entry.is_initiator());
        assert_eq!(entry.handshake_payload(), Some([0x11, 0x22].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 1_250);

        let mut awaiting_handshake = HandshakeState::new_xk_responder(local.keypair());
        awaiting_handshake.set_local_epoch([2u8; 8]);
        assert!(
            sessions
                .install_awaiting_msg3_session(
                    peer_addr,
                    local.pubkey_full(),
                    awaiting_handshake,
                    vec![0x33],
                    2_000,
                    500,
                )
                .is_some(),
            "awaiting-msg3 install replaces the old initiating entry"
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("awaiting-msg3 session should be installed");
        assert!(entry.is_awaiting_msg3());
        assert!(!entry.is_initiator());
        assert_eq!(entry.handshake_payload(), Some([0x33].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 2_500);

        let (initiator_session, _) = make_xk_session_pair(&local, &peer);
        let mut entry = initiating_entry(&local, &peer);
        let _ = entry.take_state();
        entry.establish(initiator_session, 3_000);
        entry.set_handshake_payload(vec![0x44, 0x55], 3_750);
        assert!(
            sessions.insert(peer_addr, entry).is_some(),
            "established initiator install replaces the old awaiting-msg3 entry"
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("established initiator session should be installed");
        assert!(entry.is_established());
        assert!(entry.is_initiator());
        assert_eq!(entry.session_start_ms(), 3_000);
        assert_eq!(entry.handshake_payload(), Some([0x44, 0x55].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 3_750);

    }

    #[test]
    fn session_registry_owns_rekey_session_installation_and_abandon() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_addr = *peer.node_addr();
        let mut sessions = crate::node::SessionRegistry::default();

        assert!(
            sessions
                .insert(peer_addr, established_entry(&local, &peer))
                .is_none()
        );
        let mut rekey_handshake = HandshakeState::new_xk_responder(local.keypair());
        rekey_handshake.set_local_epoch([3u8; 8]);
        assert!(sessions.install_rekey_responder_awaiting_msg3(
            &peer_addr,
            rekey_handshake,
            vec![0xaa],
            5_000,
            125,
        ));
        let entry = sessions
            .get(&peer_addr)
            .expect("rekey awaiting-msg3 state should remain installed");
        assert!(entry.has_rekey_in_progress());
        assert!(!entry.is_rekey_initiator());
        assert_eq!(entry.handshake_payload(), Some([0xaa].as_slice()));
        assert_eq!(entry.next_resend_at_ms(), 5_125);
        assert!(entry.is_rekey_dampened(5_100, 500));

        assert!(sessions.abandon_rekey(&peer_addr));
        let entry = sessions
            .get(&peer_addr)
            .expect("session should remain after abandon");
        assert!(!entry.has_rekey_in_progress());
        assert!(entry.pending_new_session().is_none());
        assert_eq!(entry.handshake_payload(), None);

        let (pending_session, _) = make_xk_session_pair(&local, &peer);
        let mut entry = established_entry(&local, &peer);
        entry.set_handshake_payload(vec![0xbb], 6_050);
        assert!(
            sessions
                .install_rekey_initiator_pending_session(
                    peer_addr,
                    entry,
                    pending_session,
                    vec![0xcc, 0xdd],
                    6_000,
                    250,
                )
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("initiator pending rekey should be installed");
        assert!(entry.pending_new_session().is_some());
        assert_eq!(entry.rekey_completed_ms(), 6_000);
        assert_eq!(entry.handshake_payload(), None);
        assert_eq!(entry.rekey_msg3_payload(), Some([0xcc, 0xdd].as_slice()));
        assert_eq!(entry.rekey_msg3_next_resend_ms(), 6_250);

        let (_, pending_session) = make_xk_session_pair(&peer, &local);
        let mut entry = established_entry(&local, &peer);
        entry.set_handshake_payload(vec![0xee], 7_050);
        assert!(
            sessions
                .install_rekey_responder_pending_session(peer_addr, entry, pending_session)
                .is_some()
        );
        let entry = sessions
            .get(&peer_addr)
            .expect("responder pending rekey should be installed");
        assert!(entry.pending_new_session().is_some());
        assert_eq!(entry.handshake_payload(), None);
        assert_eq!(entry.rekey_msg3_payload(), None);
    }
