use super::*;

#[test]
fn test_xk_full_handshake() {
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();
    let initiator_epoch = generate_epoch();
    let responder_epoch = generate_epoch();

    let responder_pub = responder_keypair.public_key();

    // XK: initiator knows responder's static, responder learns initiator's in msg3
    let mut initiator = HandshakeState::new_xk_initiator(initiator_keypair, responder_pub);
    initiator.set_local_epoch(initiator_epoch);
    let mut responder = HandshakeState::new_xk_responder(responder_keypair);
    responder.set_local_epoch(responder_epoch);

    assert_eq!(initiator.role(), HandshakeRole::Initiator);
    assert_eq!(responder.role(), HandshakeRole::Responder);

    // Initially, responder doesn't know initiator's identity
    assert!(responder.remote_static().is_none());

    // Message 1: Initiator -> Responder (e, es)
    let msg1 = initiator.write_xk_message_1().unwrap();
    assert_eq!(msg1.len(), XK_HANDSHAKE_MSG1_SIZE);
    assert_eq!(msg1.len(), 33); // ephemeral only

    responder.read_xk_message_1(&msg1).unwrap();

    // After msg1: responder still doesn't know initiator's identity (XK property)
    assert!(responder.remote_static().is_none());
    assert!(responder.remote_epoch().is_none());

    // Message 2: Responder -> Initiator (e, ee + epoch)
    let msg2 = responder.write_xk_message_2().unwrap();
    assert_eq!(msg2.len(), XK_HANDSHAKE_MSG2_SIZE);
    assert_eq!(msg2.len(), 57); // 33 ephemeral + 24 encrypted epoch

    initiator.read_xk_message_2(&msg2).unwrap();

    // After msg2: initiator learned responder's epoch
    assert_eq!(initiator.remote_epoch(), Some(responder_epoch));
    // Neither side is complete yet
    assert!(!initiator.is_complete());
    assert!(!responder.is_complete());

    // Message 3: Initiator -> Responder (s, se + epoch)
    let msg3 = initiator.write_xk_message_3().unwrap();
    assert_eq!(msg3.len(), XK_HANDSHAKE_MSG3_SIZE);
    assert_eq!(msg3.len(), 73); // 49 encrypted static + 24 encrypted epoch

    responder.read_xk_message_3(&msg3).unwrap();

    // Both should be complete now
    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    // After msg3: responder now knows initiator's identity
    assert!(responder.remote_static().is_some());
    assert_eq!(
        responder.remote_static().unwrap(),
        &initiator_keypair.public_key()
    );

    // Responder learned initiator's epoch from msg3
    assert_eq!(responder.remote_epoch(), Some(initiator_epoch));

    // Handshake hashes should match
    assert_eq!(initiator.handshake_hash(), responder.handshake_hash());

    // Convert to sessions
    let mut initiator_session = initiator.into_session().unwrap();
    let mut responder_session = responder.into_session().unwrap();

    // Test bidirectional encryption
    let plaintext = b"Hello via XK!";
    let ciphertext = initiator_session.encrypt(plaintext).unwrap();
    let decrypted = responder_session.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);

    let plaintext2 = b"XK reply!";
    let ciphertext2 = responder_session.encrypt(plaintext2).unwrap();
    let decrypted2 = initiator_session.decrypt(&ciphertext2).unwrap();
    assert_eq!(decrypted2, plaintext2);
}

#[test]
fn test_xk_message_sizes() {
    assert_eq!(XK_HANDSHAKE_MSG1_SIZE, 33); // ephemeral only
    assert_eq!(XK_HANDSHAKE_MSG2_SIZE, 33 + 24); // ephemeral + encrypted epoch
    assert_eq!(XK_HANDSHAKE_MSG3_SIZE, 33 + 16 + 24); // encrypted static + encrypted epoch
}

#[test]
fn test_xk_identity_timing() {
    // XK property: responder doesn't learn initiator identity until msg3
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();

    let mut initiator =
        HandshakeState::new_xk_initiator(initiator_keypair, responder_keypair.public_key());
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_xk_responder(responder_keypair);
    responder.set_local_epoch(generate_epoch());

    // Before any messages
    assert!(responder.remote_static().is_none());

    // After msg1
    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    assert!(
        responder.remote_static().is_none(),
        "XK: responder should NOT know identity after msg1"
    );

    // After msg2
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    assert!(
        responder.remote_static().is_none(),
        "XK: responder should NOT know identity after msg2"
    );

    // After msg3
    let msg3 = initiator.write_xk_message_3().unwrap();
    responder.read_xk_message_3(&msg3).unwrap();
    assert!(
        responder.remote_static().is_some(),
        "XK: responder should know identity after msg3"
    );
    assert_eq!(
        responder.remote_static().unwrap(),
        &initiator_keypair.public_key()
    );
}

#[test]
fn test_xk_wrong_state_errors() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    // Initiator can't read XK msg1
    let mut initiator = HandshakeState::new_xk_initiator(keypair1, keypair2.public_key());
    initiator.set_local_epoch(generate_epoch());
    assert!(
        initiator
            .read_xk_message_1(&[0u8; XK_HANDSHAKE_MSG1_SIZE])
            .is_err()
    );

    // Initiator can't write msg2
    assert!(initiator.write_xk_message_2().is_err());

    // Initiator can't write msg3 before msg2
    assert!(initiator.write_xk_message_3().is_err());

    // Responder can't write msg1
    let mut responder = HandshakeState::new_xk_responder(keypair2);
    responder.set_local_epoch(generate_epoch());
    assert!(responder.write_xk_message_1().is_err());

    // Responder can't read msg3 before msg2
    assert!(
        responder
            .read_xk_message_3(&[0u8; XK_HANDSHAKE_MSG3_SIZE])
            .is_err()
    );
}

#[test]
fn test_xk_handshake_hash_differs_from_ik() {
    // XK and IK should produce different handshake hashes (different protocol names)
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let epoch1 = generate_epoch();
    let epoch2 = generate_epoch();

    // Complete an IK handshake
    let mut ik_init = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    ik_init.set_local_epoch(epoch1);
    let mut ik_resp = HandshakeState::new_responder(keypair2);
    ik_resp.set_local_epoch(epoch2);
    let msg1 = ik_init.write_message_1().unwrap();
    ik_resp.read_message_1(&msg1).unwrap();
    let msg2 = ik_resp.write_message_2().unwrap();
    ik_init.read_message_2(&msg2).unwrap();
    let ik_hash = ik_init.handshake_hash();

    // Complete an XK handshake with the same keys
    let mut xk_init = HandshakeState::new_xk_initiator(keypair1, keypair2.public_key());
    xk_init.set_local_epoch(epoch1);
    let mut xk_resp = HandshakeState::new_xk_responder(keypair2);
    xk_resp.set_local_epoch(epoch2);
    let msg1 = xk_init.write_xk_message_1().unwrap();
    xk_resp.read_xk_message_1(&msg1).unwrap();
    let msg2 = xk_resp.write_xk_message_2().unwrap();
    xk_init.read_xk_message_2(&msg2).unwrap();
    let msg3 = xk_init.write_xk_message_3().unwrap();
    xk_resp.read_xk_message_3(&msg3).unwrap();
    let xk_hash = xk_init.handshake_hash();

    assert_ne!(
        ik_hash, xk_hash,
        "IK and XK should produce different handshake hashes"
    );
}

#[test]
fn test_xk_multiple_messages_after_handshake() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut initiator = HandshakeState::new_xk_initiator(keypair1, keypair2.public_key());
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_xk_responder(keypair2);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator.write_xk_message_3().unwrap();
    responder.read_xk_message_3(&msg3).unwrap();

    let mut init_session = initiator.into_session().unwrap();
    let mut resp_session = responder.into_session().unwrap();

    // Send many messages
    for i in 0..100 {
        let msg = format!("XK message {}", i);
        let ct = init_session.encrypt(msg.as_bytes()).unwrap();
        let pt = resp_session.decrypt(&ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    assert_eq!(init_session.send_nonce(), 100);
    assert_eq!(resp_session.recv_nonce(), 100);
}

#[test]
fn test_xk_with_odd_parity_responder() {
    let secp = secp256k1::Secp256k1::new();

    // Node B (responder) - odd parity key
    let sk_b = secp256k1::SecretKey::from_slice(
        &hex::decode("b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0").unwrap(),
    )
    .unwrap();
    let kp_b = secp256k1::Keypair::from_secret_key(&secp, &sk_b);
    let (xonly_b, parity_b) = kp_b.public_key().x_only_public_key();
    assert_eq!(
        parity_b,
        Parity::Odd,
        "Test requires odd-parity responder key"
    );

    // Node A (initiator)
    let sk_a = secp256k1::SecretKey::from_slice(
        &hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap(),
    )
    .unwrap();
    let kp_a = secp256k1::Keypair::from_secret_key(&secp, &sk_a);

    // Simulate npub path: x-only → assumed even parity
    let assumed_even_b = xonly_b.public_key(Parity::Even);

    let mut initiator = HandshakeState::new_xk_initiator(kp_a, assumed_even_b);
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_xk_responder(kp_b);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator.write_xk_message_3().unwrap();
    responder.read_xk_message_3(&msg3).unwrap();

    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    let mut sender = initiator.into_session().unwrap();
    let mut receiver = responder.into_session().unwrap();

    let counter = sender.current_send_counter();
    let ciphertext = sender.encrypt(b"xk parity test").unwrap();
    let plaintext = receiver
        .decrypt_with_replay_check(&ciphertext, counter)
        .unwrap();
    assert_eq!(plaintext, b"xk parity test");
}
