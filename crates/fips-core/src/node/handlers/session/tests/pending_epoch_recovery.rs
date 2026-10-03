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

    async fn complete_rekey(left: &mut Node, right: &mut Node) {
        let source = *left.node_addr();
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
        let msg3 = left
            .sessions
            .get(&destination)
            .unwrap()
            .rekey_msg3_payload()
            .unwrap()
            .to_vec();
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
        let plaintext =
            fsp_prepend_inner_header(100, SessionMessageType::SenderReport.to_byte(), 0, &[0; 46]);
        let header = build_fsp_header(
            counter,
            if k_bit { FSP_FLAG_K } else { 0 },
            plaintext.len().try_into().unwrap(),
        );
        let ciphertext = crate::noise::seal(Some(&cipher), counter, &header, &plaintext).unwrap();
        let mut wire = header.to_vec();
        wire.extend(ciphertext);
        let raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(1),
                TransportAddr::from_string("192.0.2.1:2121"),
                PacketBuffer::new(wire),
                Node::now_ms(),
            ),
        )
        .with_fsp_source(source)
        .with_previous_hop(source);
        receive_epoch_wire(right, raw).await
    }

    #[tokio::test]
    async fn recovery_rekey_after_lost_cutover_confirmation_authenticates() {
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
        assert!(!right.sessions.should_defer_incoming_session_rekey(&source));

        complete_rekey(&mut left, &mut right).await;
        // The second handshake is cryptographically identical at both ends.
        // Its first authenticated packet must still select the matching keys,
        // even though only the responder promoted the preceding epoch.
        // The responder can probe first with the opposite flag. Authentication
        // must not make both endpoints swap flags and diverge a second time.
        assert_eq!(deliver_report(&right, &mut left, true).await, 0);
        assert!(
            left.sessions
                .get(&destination)
                .unwrap()
                .pending_new_session()
                .is_some()
        );
        assert_eq!(deliver_report(&left, &mut right, true).await, 1);
        assert_eq!(deliver_report(&right, &mut left, false).await, 1);
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
}
