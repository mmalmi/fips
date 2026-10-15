#[tokio::test]
async fn confirmation_authenticates_only_the_pending_initiator_epoch() {
    let (mut left, mut right) = endpoints();
    let source = *left.node_addr();
    let destination = *right.node_addr();
    complete_rekey(&mut left, &mut right).await;
    assert!(
        right
            .sessions
            .get(&source)
            .unwrap()
            .rekey_confirmation()
            .is_none()
    );
    let (_, wrong_epoch) = make_xk_session_pair(&left.identity, &right.identity);
    let stale = SessionConfirm::for_fresh_session(&wrong_epoch).unwrap();
    right.handle_session_confirmation(&source, &source, stale.as_bytes());
    assert!(
        right
            .sessions
            .get(&source)
            .unwrap()
            .pending_new_session()
            .is_some()
    );
    left.handle_session_confirmation(&destination, &destination, stale.as_bytes());
    assert!(
        left.sessions
            .get(&destination)
            .unwrap()
            .pending_new_session()
            .is_some()
    );

    assert_eq!(deliver_report(&left, &mut right, true).await, 1);
    let proof = right
        .sessions
        .get(&source)
        .unwrap()
        .rekey_confirmation()
        .unwrap();
    assert_eq!(
        deliver_control(&left, &mut right, false, SessionMessageType::CoordsWarmup).await,
        0,
        "an old epoch must not elicit the current epoch's proof"
    );
    assert!(right.coords_response_rate_limiter.should_send(&source));
    right.coords_response_rate_limiter =
        crate::proto::rate_limit::RoutingErrorRateLimiter::with_interval(
            std::time::Duration::from_secs(2),
        );
    for _ in 0..2 {
        assert_eq!(
            deliver_control(&left, &mut right, true, SessionMessageType::CoordsWarmup).await,
            1
        );
        assert!(
            !right.coords_response_rate_limiter.should_send(&source),
            "immediate retries are bounded"
        );
        assert_eq!(
            right.sessions.get(&source).unwrap().rekey_confirmation(),
            Some(proof)
        );
        assert_eq!(
            right
                .sessions
                .get(&source)
                .unwrap()
                .send_counter_authority()
                .unwrap()
                .current(),
            1
        );
    }
    for index in 0..12 {
        let mut tampered = proof.as_bytes().to_vec();
        tampered[index] ^= 1;
        left.handle_session_confirmation(&destination, &destination, &tampered);
    }
    let mut bad_tag = proof.as_bytes().to_vec();
    bad_tag[27] ^= 1;
    left.handle_session_confirmation(&destination, &destination, &bad_tag);
    assert!(
        left.sessions
            .get(&destination)
            .unwrap()
            .pending_new_session()
            .is_some()
    );
    let before = left.dataplane.fsp_mmp_snapshot(&destination).unwrap();
    left.handle_session_confirmation(&destination, &destination, proof.as_bytes());
    assert!(
        left.sessions
            .get(&destination)
            .unwrap()
            .pending_new_session()
            .is_none()
    );
    assert_eq!(
        left.sessions.get(&destination).unwrap().current_k_bit(),
        right.sessions.get(&source).unwrap().current_k_bit()
    );
    let after = left.dataplane.fsp_mmp_snapshot(&destination).unwrap();
    assert_eq!(
        (before.tx_packets, before.rx_packets),
        (after.tx_packets, after.rx_packets),
        "key confirmation must not invent a delivery measurement"
    );
    left.handle_session_confirmation(&destination, &destination, proof.as_bytes());
    assert!(
        !left
            .dataplane
            .authenticate_fsp_owner_confirmation(&destination, &proof, true)
    );
    assert_eq!(deliver_report(&right, &mut left, false).await, 1);
}

#[test]
fn cached_confirmation_reserves_only_the_first_nonce_without_mmp_gaps() {
    use crate::mmp::{receiver::ReceiverState, sender::SenderState};
    let left = Identity::generate();
    let right = Identity::generate();
    let (receiver, sender) = make_xk_session_pair(&left, &right);
    let proof = SessionConfirm::for_fresh_session(&sender).unwrap();
    let authority = sender.send_counter_authority();
    assert_eq!(authority.current(), 1);
    let mut sent = SenderState::new();
    let mut received = ReceiverState::new(16);
    let now = Instant::now();
    for expected in 1..=3 {
        // A lost proof is retried byte-for-byte without allocating another nonce.
        assert_eq!(SessionConfirm::decode(proof.as_bytes()), Some(proof));
        let counter = authority.reserve().unwrap();
        assert_eq!(counter, expected);
        sent.record_sent(counter, 100, 64);
        received.record_recv(counter, 100, 64, false, now);
    }
    let sent = sent.build_report(now).unwrap();
    let received = received.build_report(now).unwrap();
    assert_eq!(
        (sent.interval_start_counter, sent.interval_end_counter),
        (1, 3)
    );
    assert_eq!(sent.cumulative_packets_sent, 3);
    assert_eq!(received.cumulative_packets_recv, 3);
    assert_eq!(received.burst_loss_count, 0);
    assert!(
        crate::noise::open(
            receiver.recv_cipher_clone().as_ref(),
            0,
            &proof.as_bytes()[..12],
            &proof.as_bytes()[12..]
        )
        .unwrap()
        .is_empty()
    );
    let mut other_phase = proof.as_bytes()[..12].to_vec();
    other_phase[0] = 0;
    assert!(
        crate::noise::open(
            receiver.recv_cipher_clone().as_ref(),
            0,
            &other_phase,
            &proof.as_bytes()[12..]
        )
        .is_err(),
        "phase is authenticated"
    );
}
