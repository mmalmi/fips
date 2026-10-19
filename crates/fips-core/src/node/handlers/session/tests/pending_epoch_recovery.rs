mod pending_epoch_recovery {
    use super::*;

    fn endpoints() -> (Node, Node) {
        let a = Identity::from_secret_bytes(&[41; 32]).unwrap();
        let b = Identity::from_secret_bytes(&[42; 32]).unwrap();
        let (ab, ba) = make_xk_session_pair(&a, &b);
        let mut left = Node::with_identity(a, crate::config::Config::new()).unwrap();
        let mut right = Node::with_identity(b, crate::config::Config::new()).unwrap();
        // Match the real initial handshake helper's process epochs. Neither
        // endpoint restarts in this scenario.
        left.startup_epoch = [1; 8];
        right.startup_epoch = [2; 8];
        let identities = [
            PeerIdentity::from_pubkey_full(left.identity.pubkey_full()),
            PeerIdentity::from_pubkey_full(right.identity.pubkey_full()),
        ];
        for (node, peer, session, initiator) in [
            (&mut left, identities[1], ab, true),
            (&mut right, identities[0], ba, false),
        ] {
            let mut entry = SessionEntry::new(
                *peer.node_addr(),
                peer.pubkey_full(),
                EndToEndState::Established(session),
                Node::now_ms(),
                initiator,
            );
            entry.mark_established(Node::now_ms());
            node.sessions.insert(*peer.node_addr(), entry);
            assert!(node.sync_dataplane_fsp_owner_from_current_session(peer.node_addr(), 0));
        }
        (left, right)
    }

    fn rekey_setup(left: &mut Node, right: &Node) -> Vec<u8> {
        let destination = *right.node_addr();
        let mut handshake =
            HandshakeState::new_xk_initiator(left.identity.keypair(), right.identity.pubkey_full());
        handshake.set_local_epoch(left.startup_epoch);
        let msg1 = handshake.write_xk_message_1().unwrap();
        let setup = SessionSetup::new(
            left.tree_state.my_coords().clone(),
            right.tree_state.my_coords().clone(),
        )
        .with_handshake(msg1)
        .encode();
        let entry = left.sessions.get_mut(&destination).unwrap();
        entry.set_rekey_state(handshake, true);
        entry.set_handshake_payload(setup.clone(), Node::now_ms() + 1_000);
        setup
    }

    async fn begin_rekey(left: &mut Node, right: &mut Node) -> Vec<u8> {
        let source = *left.node_addr();
        let destination = *right.node_addr();
        let setup = rekey_setup(left, right);

        // Deliver the exact real handshake payloads. No transport is installed,
        // so replies remain in their production retransmission state until
        // explicitly delivered here; return confirmation can be lost exactly.
        right
            .handle_session_setup(&source, &source, &setup[FSP_COMMON_PREFIX_SIZE..])
            .await;
        let ack = right
            .sessions
            .get(&source)
            .unwrap()
            .handshake_payload()
            .unwrap()
            .to_vec();
        left.handle_session_ack(&destination, &destination, &ack[FSP_COMMON_PREFIX_SIZE..])
            .await;
        left.sessions
            .get(&destination)
            .unwrap()
            .rekey_msg3_payload()
            .unwrap()
            .to_vec()
    }

    async fn complete_rekey(left: &mut Node, right: &mut Node) {
        let source = *left.node_addr();
        let destination = *right.node_addr();
        let msg3 = begin_rekey(left, right).await;
        right
            .handle_session_msg3(&source, &source, &msg3[FSP_COMMON_PREFIX_SIZE..])
            .await;
        assert_eq!(
            left.sessions
                .get(&destination)
                .unwrap()
                .pending_new_session()
                .unwrap()
                .handshake_hash(),
            right
                .sessions
                .get(&source)
                .unwrap()
                .pending_new_session()
                .unwrap()
                .handshake_hash(),
            "both endpoints must complete the same authenticated handshake",
        );
    }

    async fn deliver_report(left: &Node, right: &mut Node, pending: bool) -> usize {
        deliver_control(left, right, pending, SessionMessageType::SenderReport).await
    }

    async fn deliver_control(
        left: &Node,
        right: &mut Node,
        pending: bool,
        kind: SessionMessageType,
    ) -> usize {
        let raw = control_wire(left, right, pending, kind);
        receive_epoch_wire(right, raw).await
    }

    fn control_wire(
        left: &Node,
        right: &Node,
        pending: bool,
        kind: SessionMessageType,
    ) -> crate::dataplane::DataplaneRawIngress {
        use crate::dataplane::{DataplaneRawIngress, PacketProtocol};
        use crate::node::session_wire::{FSP_FLAG_K, build_fsp_header};
        use crate::transport::{ReceivedPacket, TransportAddr, TransportId};

        let source = *left.node_addr();
        let entry = left.sessions.get(right.node_addr()).unwrap();
        let (cipher, counter, k_bit) = if pending {
            let session = entry.pending_new_session().unwrap();
            (
                session.send_cipher_clone().unwrap(),
                session.take_send_counter().unwrap(),
                !entry.current_k_bit(),
            )
        } else {
            (
                entry.fsp_crypto_keys().unwrap().1,
                entry.send_counter_authority().unwrap().reserve().unwrap(),
                entry.current_k_bit(),
            )
        };
        let body: &[u8] = if kind == SessionMessageType::CoordsWarmup {
            &[]
        } else {
            &[0; 46]
        };
        let plaintext = fsp_prepend_inner_header(100, kind.to_byte(), 0, body);
        let header = build_fsp_header(
            counter,
            if k_bit { FSP_FLAG_K } else { 0 },
            plaintext.len().try_into().unwrap(),
        );
        let ciphertext = crate::noise::seal(Some(&cipher), counter, &header, &plaintext).unwrap();
        let mut wire = header.to_vec();
        wire.extend(ciphertext);
        DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(1),
                TransportAddr::from_string("192.0.2.1:2121"),
                PacketBuffer::new(wire),
                Node::now_ms(),
            ),
        )
        .with_fsp_source(source)
        .with_previous_hop(source)
    }

    #[tokio::test]
    async fn recovery_rekey_after_lost_cutover_confirmation_authenticates() {
        recover_after_lost_confirmation(false).await;
    }

    #[tokio::test]
    async fn authenticated_restart_recovers_during_previous_epoch_drain() {
        restart_during_drain(false).await;
    }

    #[tokio::test]
    async fn authenticated_restart_recovers_with_a_queued_epoch() {
        restart_during_drain(true).await;
    }

    async fn restart_during_drain(with_queued_epoch: bool) {
        let (mut left, mut right) = endpoints();
        let source = *left.node_addr();
        let destination = *right.node_addr();
        complete_rekey(&mut left, &mut right).await;
        assert_eq!(deliver_report(&left, &mut right, true).await, 1);
        let proof = right
            .sessions
            .get(&source)
            .unwrap()
            .rekey_confirmation()
            .unwrap();
        left.handle_session_confirmation(&destination, &destination, proof.as_bytes());
        assert!(left.sessions.get(&destination).unwrap().is_draining());
        assert!(right.sessions.get(&source).unwrap().is_draining());
        if with_queued_epoch {
            complete_rekey(&mut left, &mut right).await;
        }

        // Only the sender restarts. The recipient must retain its live keys
        // until the new process epoch is authenticated by Noise msg3.
        left.remove_dataplane_fsp_owner(&destination);
        left.sessions.remove(&destination).unwrap();
        left.startup_epoch[0] ^= 0xff;
        let mut handshake =
            HandshakeState::new_xk_initiator(left.identity.keypair(), right.identity.pubkey_full());
        handshake.set_local_epoch(left.startup_epoch);
        let setup = SessionSetup::new(
            left.tree_state.my_coords().clone(),
            right.tree_state.my_coords().clone(),
        )
        .with_handshake(handshake.write_xk_message_1().unwrap())
        .encode();
        left.sessions.install_initiating_session(
            destination,
            right.identity.pubkey_full(),
            handshake,
            setup.clone(),
            Node::now_ms(),
            1_000,
        );
        let original = right
            .sessions
            .get(&source)
            .unwrap()
            .handshake_hash()
            .copied();
        let original_pending = right
            .sessions
            .get(&source)
            .unwrap()
            .pending_new_session()
            .map(|session| *session.handshake_hash());
        right
            .handle_session_setup(&source, &source, &setup[FSP_COMMON_PREFIX_SIZE..])
            .await;
        assert_eq!(
            right
                .sessions
                .get(&source)
                .unwrap()
                .handshake_hash()
                .copied(),
            original,
            "an unauthenticated setup must preserve the current epoch"
        );
        assert!(right.sessions.get(&source).unwrap().is_draining());
        assert_eq!(
            right
                .sessions
                .get(&source)
                .unwrap()
                .pending_new_session()
                .map(|session| *session.handshake_hash()),
            original_pending,
            "an unauthenticated setup must preserve completed pending keys"
        );
        let ack = right
            .sessions
            .get(&source)
            .unwrap()
            .handshake_payload()
            .expect("restart handshake must proceed during drain")
            .to_vec();
        left.handle_session_ack(&destination, &destination, &ack[FSP_COMMON_PREFIX_SIZE..])
            .await;
        let msg3 = left
            .sessions
            .get(&destination)
            .unwrap()
            .handshake_payload()
            .unwrap()
            .to_vec();
        right
            .handle_session_msg3(&source, &source, &msg3[FSP_COMMON_PREFIX_SIZE..])
            .await;
        for (node, remote) in [(&left, destination), (&right, source)] {
            let entry = node.sessions.get(&remote).unwrap();
            assert!(entry.is_established());
            assert!(!entry.current_k_bit());
            assert!(!entry.is_draining());
            assert!(entry.pending_new_session().is_none());
        }
        assert_eq!(
            left.sessions.get(&destination).unwrap().handshake_hash(),
            right.sessions.get(&source).unwrap().handshake_hash()
        );
        assert_eq!(deliver_report(&left, &mut right, false).await, 1);
    }

    #[tokio::test]
    async fn invalid_recovery_handshake_preserves_completed_pending_keys() {
        let (mut left, mut right) = endpoints();
        let source = *left.node_addr();
        complete_rekey(&mut left, &mut right).await;
        let entry = right.sessions.get(&source).unwrap();
        let original = entry.handshake_hash().copied();
        let pending = *entry.pending_new_session().unwrap().handshake_hash();
        let raw = control_wire(&left, &right, true, SessionMessageType::SenderReport);
        let mut msg3 = begin_rekey(&mut left, &mut right).await;
        *msg3.last_mut().unwrap() ^= 1;
        right
            .handle_session_msg3(&source, &source, &msg3[FSP_COMMON_PREFIX_SIZE..])
            .await;
        let entry = right.sessions.get(&source).unwrap();
        assert!(!entry.has_rekey_in_progress());
        assert_eq!(entry.handshake_hash().copied(), original);
        assert_eq!(
            entry.pending_new_session().unwrap().handshake_hash(),
            &pending
        );
        assert_eq!(receive_epoch_wire(&mut right, raw).await, 1);
        assert_eq!(
            right.sessions.get(&source).unwrap().handshake_hash(),
            Some(&pending)
        );
    }

    #[tokio::test]
    async fn pending_cutover_probe_survives_a_speculative_handshake() {
        let (mut left, mut right) = endpoints();
        let source = *left.node_addr();
        let destination = *right.node_addr();
        complete_rekey(&mut left, &mut right).await;
        let pending = *left
            .sessions
            .get(&destination)
            .unwrap()
            .pending_new_session()
            .unwrap()
            .handshake_hash();
        let setup = rekey_setup(&mut right, &left);
        left.handle_session_setup(&destination, &destination, &setup[FSP_COMMON_PREFIX_SIZE..])
            .await;
        let entry = left.sessions.get_mut(&destination).unwrap();
        assert!(entry.has_rekey_in_progress());
        entry.set_rekey_completed_ms(Node::now_ms().saturating_sub(3_000));
        assert!(entry.rekey_probe_due(Node::now_ms(), 2_000, 1_000));
        left.check_session_rekey().await;
        let entry = left.sessions.get(&destination).unwrap();
        assert!(entry.has_rekey_in_progress());
        assert!(!entry.rekey_probe_due(Node::now_ms(), 2_000, 1_000));
        assert_eq!(
            deliver_control(&left, &mut right, true, SessionMessageType::CoordsWarmup).await,
            1
        );
        let proof = right
            .sessions
            .get(&source)
            .unwrap()
            .rekey_confirmation()
            .unwrap();
        left.handle_session_confirmation(&destination, &destination, proof.as_bytes());
        for (node, remote) in [(&left, destination), (&right, source)] {
            let entry = node.sessions.get(&remote).unwrap();
            assert!(entry.pending_new_session().is_none());
            assert_eq!(entry.handshake_hash(), Some(&pending));
        }
    }

    #[tokio::test]
    async fn delayed_pending_packet_preserves_a_newer_recovery_handshake() {
        let (mut left, mut right) = endpoints();
        let source = *left.node_addr();
        let destination = *right.node_addr();
        complete_rekey(&mut left, &mut right).await;
        let delayed = control_wire(&left, &right, true, SessionMessageType::SenderReport);
        let msg3 = begin_rekey(&mut left, &mut right).await;
        assert_eq!(receive_epoch_wire(&mut right, delayed).await, 1);
        assert!(
            right.sessions.get(&source).unwrap().has_rekey_in_progress(),
            "older authenticated traffic must preserve the newer handshake"
        );
        right
            .handle_session_msg3(&source, &source, &msg3[FSP_COMMON_PREFIX_SIZE..])
            .await;
        assert_eq!(
            left.sessions
                .get(&destination)
                .unwrap()
                .pending_new_session()
                .unwrap()
                .handshake_hash(),
            right
                .sessions
                .get(&source)
                .unwrap()
                .pending_new_session()
                .unwrap()
                .handshake_hash()
        );
        // The recipient just promoted the older pending keys. Retire that
        // ordinary drain before publishing the newer completed epoch.
        right.sessions.get_mut(&source).unwrap().complete_drain();
        assert!(right.set_dataplane_fsp_owner_epoch(&source, true, None));
        assert!(right.sync_dataplane_fsp_pending_epoch(&source));
        assert_eq!(deliver_report(&left, &mut right, true).await, 1);
        let proof = right
            .sessions
            .get(&source)
            .unwrap()
            .rekey_confirmation()
            .unwrap();
        left.handle_session_confirmation(&destination, &destination, proof.as_bytes());
        assert_eq!(
            left.sessions.get(&destination).unwrap().handshake_hash(),
            right.sessions.get(&source).unwrap().handshake_hash()
        );
        assert_eq!(deliver_report(&right, &mut left, false).await, 1);
    }

    #[tokio::test]
    async fn empty_confirmation_recovers_asymmetric_key_bits() {
        recover_after_lost_confirmation(true).await;
    }

    #[tokio::test]
    async fn same_process_rekey_preserves_previous_epoch_until_drain_finishes() {
        let (mut left, mut right) = endpoints();
        let source = *left.node_addr();
        let destination = *right.node_addr();
        complete_rekey(&mut left, &mut right).await;
        // Age the real drain metadata so the production tick can retire it
        // later in this test without a wall-clock sleep.
        for (node, remote) in [(&mut left, destination), (&mut right, source)] {
            assert!(
                node.sessions
                    .get_mut(&remote)
                    .unwrap()
                    .cutover_to_new_session(1)
            );
            assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote, 0));
        }
        let original = right
            .sessions
            .get(&source)
            .unwrap()
            .handshake_hash()
            .copied();
        complete_rekey(&mut left, &mut right).await;
        let raw = control_wire(&left, &right, true, SessionMessageType::SenderReport);
        assert_eq!(
            try_receive_epoch_wire(&mut right, raw).await,
            None,
            "a new pending key must not occupy the draining epoch's K slot"
        );
        assert_eq!(
            deliver_report(&left, &mut right, false).await,
            1,
            "the current epoch must remain usable during the handshake"
        );
        assert_eq!(
            right
                .sessions
                .get(&source)
                .unwrap()
                .handshake_hash()
                .copied(),
            original
        );

        left.check_session_rekey().await;
        right.check_session_rekey().await;
        assert!(!right.sessions.get(&source).unwrap().is_draining());
        assert_eq!(
            deliver_report(&left, &mut right, true).await,
            1,
            "the queued epoch must become usable after ordinary drain retirement"
        );
        let proof = right
            .sessions
            .get(&source)
            .unwrap()
            .rekey_confirmation()
            .unwrap();
        left.handle_session_confirmation(&destination, &destination, proof.as_bytes());
        assert!(
            left.sessions
                .get(&destination)
                .unwrap()
                .pending_new_session()
                .is_none()
        );
        assert_eq!(
            left.sessions.get(&destination).unwrap().handshake_hash(),
            right.sessions.get(&source).unwrap().handshake_hash()
        );
    }

    async fn recover_after_lost_confirmation(explicit_confirmation: bool) {
        let (mut left, mut right) = endpoints();
        let source = *left.node_addr();
        let destination = *right.node_addr();
        complete_rekey(&mut left, &mut right).await;
        assert_eq!(deliver_report(&left, &mut right, true).await, 1);
        eprintln!("first rekey authenticated; testing recovery after lost confirmation");
        assert!(right.sessions.get(&source).unwrap().current_k_bit());
        assert!(!left.sessions.get(&destination).unwrap().current_k_bit());

        // The responder has authenticated the new epoch, but its confirmation
        // never returns. Apply normal drain expiry without a 45-second sleep;
        // age only the initiator's pending-completion timestamp for recovery.
        right.sessions.get_mut(&source).unwrap().complete_drain();
        assert!(right.set_dataplane_fsp_owner_epoch(&source, true, None));
        let now = Node::now_ms();
        let entry = left.sessions.get_mut(&destination).unwrap();
        entry.set_rekey_completed_ms(now.saturating_sub(6_000));
        assert!(session_can_recover_from_decrypt_failures(entry, now));
        complete_rekey(&mut left, &mut right).await;
        // The second handshake is cryptographically identical at both ends.
        // Its first authenticated packet must still select the matching keys,
        // even though only the responder promoted the preceding epoch.
        // The responder can probe first with the opposite flag. Authentication
        // must not make both endpoints swap flags and diverge a second time.
        assert_eq!(deliver_report(&right, &mut left, true).await, 0);
        assert_eq!(
            deliver_control(&right, &mut left, true, SessionMessageType::CoordsWarmup).await,
            0
        );
        assert!(
            left.sessions
                .get(&destination)
                .unwrap()
                .pending_new_session()
                .is_some()
        );
        assert_eq!(deliver_report(&left, &mut right, true).await, 1);
        if explicit_confirmation {
            let proof = right
                .sessions
                .get(&source)
                .unwrap()
                .rekey_confirmation()
                .unwrap();
            left.handle_session_confirmation(&destination, &destination, proof.as_bytes());
        } else {
            assert_eq!(deliver_report(&right, &mut left, false).await, 1);
        }
        assert!(
            left.sessions
                .get(&destination)
                .unwrap()
                .pending_new_session()
                .is_none()
        );
        assert!(
            right
                .sessions
                .get(&source)
                .unwrap()
                .pending_new_session()
                .is_none()
        );
        assert_eq!(
            left.sessions.get(&destination).unwrap().current_k_bit(),
            right.sessions.get(&source).unwrap().current_k_bit()
        );
        assert_eq!(deliver_report(&left, &mut right, false).await, 1);
        assert_eq!(deliver_report(&right, &mut left, false).await, 1);
    }

    include!("key_confirmation.rs");
}
