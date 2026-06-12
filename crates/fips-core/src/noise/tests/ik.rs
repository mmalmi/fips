use super::*;

#[test]
fn test_full_handshake() {
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();
    let initiator_epoch = generate_epoch();
    let responder_epoch = generate_epoch();

    let responder_pub = responder_keypair.public_key();

    // Initiator knows responder's static key
    // Responder does NOT know initiator's static key (IK pattern)
    let mut initiator = HandshakeState::new_initiator(initiator_keypair, responder_pub);
    initiator.set_local_epoch(initiator_epoch);
    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(responder_epoch);

    assert_eq!(initiator.role(), HandshakeRole::Initiator);
    assert_eq!(responder.role(), HandshakeRole::Responder);

    // Initially, responder doesn't know initiator's identity
    assert!(responder.remote_static().is_none());

    // Message 1: Initiator -> Responder
    let msg1 = initiator.write_message_1().unwrap();
    assert_eq!(msg1.len(), HANDSHAKE_MSG1_SIZE);

    responder.read_message_1(&msg1).unwrap();

    // Now responder knows initiator's identity!
    assert!(responder.remote_static().is_some());
    assert_eq!(
        responder.remote_static().unwrap(),
        &initiator_keypair.public_key()
    );

    // Responder learned initiator's epoch
    assert_eq!(responder.remote_epoch(), Some(initiator_epoch));

    // Message 2: Responder -> Initiator
    let msg2 = responder.write_message_2().unwrap();
    assert_eq!(msg2.len(), HANDSHAKE_MSG2_SIZE);

    initiator.read_message_2(&msg2).unwrap();

    // Both should be complete
    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    // Initiator learned responder's epoch
    assert_eq!(initiator.remote_epoch(), Some(responder_epoch));

    // Handshake hashes should match
    assert_eq!(initiator.handshake_hash(), responder.handshake_hash());

    // Convert to sessions
    let mut initiator_session = initiator.into_session().unwrap();
    let mut responder_session = responder.into_session().unwrap();

    // Test encryption/decryption
    let plaintext = b"Hello, secure world!";

    let ciphertext = initiator_session.encrypt(plaintext).unwrap();
    let decrypted = responder_session.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);

    // Test reverse direction
    let plaintext2 = b"Hello back!";
    let ciphertext2 = responder_session.encrypt(plaintext2).unwrap();
    let decrypted2 = initiator_session.decrypt(&ciphertext2).unwrap();
    assert_eq!(decrypted2, plaintext2);
}

#[test]
fn test_multiple_messages() {
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();

    let mut initiator =
        HandshakeState::new_initiator(initiator_keypair, responder_keypair.public_key());
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    let mut initiator_session = initiator.into_session().unwrap();
    let mut responder_session = responder.into_session().unwrap();

    // Send many messages to test nonce increment
    for i in 0..100 {
        let msg = format!("Message {}", i);
        let ct = initiator_session.encrypt(msg.as_bytes()).unwrap();
        let pt = responder_session.decrypt(&ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    assert_eq!(initiator_session.send_nonce(), 100);
    assert_eq!(responder_session.recv_nonce(), 100);
}

#[test]
fn test_wrong_role_errors() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut initiator = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    initiator.set_local_epoch(generate_epoch());

    // Initiator can't read message 1
    assert!(
        initiator
            .read_message_1(&[0u8; HANDSHAKE_MSG1_SIZE])
            .is_err()
    );

    // Initiator can't write message 2 before message 1
    assert!(initiator.write_message_2().is_err());
}

#[test]
fn test_invalid_pubkey_in_msg1() {
    let keypair = generate_keypair();
    let mut responder = HandshakeState::new_responder(keypair);
    responder.set_local_epoch(generate_epoch());

    // Invalid pubkey bytes (first 33 bytes are zero)
    let invalid_msg = [0u8; HANDSHAKE_MSG1_SIZE];
    assert!(responder.read_message_1(&invalid_msg).is_err());
}

#[test]
fn test_decryption_failure_wrong_key() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let keypair3 = generate_keypair();

    // Session between 1 and 2
    let mut init1 = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    init1.set_local_epoch(generate_epoch());
    let mut resp1 = HandshakeState::new_responder(keypair2);
    resp1.set_local_epoch(generate_epoch());

    let msg1 = init1.write_message_1().unwrap();
    resp1.read_message_1(&msg1).unwrap();
    let msg2 = resp1.write_message_2().unwrap();
    init1.read_message_2(&msg2).unwrap();

    let mut session1 = init1.into_session().unwrap();

    // Session between 1 and 3
    let mut init2 = HandshakeState::new_initiator(keypair1, keypair3.public_key());
    init2.set_local_epoch(generate_epoch());
    let mut resp2 = HandshakeState::new_responder(keypair3);
    resp2.set_local_epoch(generate_epoch());

    let msg1 = init2.write_message_1().unwrap();
    resp2.read_message_1(&msg1).unwrap();
    let msg2 = resp2.write_message_2().unwrap();
    init2.read_message_2(&msg2).unwrap();

    let mut session2 = resp2.into_session().unwrap();

    // Encrypt with session 1, try to decrypt with session 2
    let ciphertext = session1.encrypt(b"test").unwrap();
    assert!(session2.decrypt(&ciphertext).is_err());
}

#[test]
fn test_cipher_state_nonce_sequence() {
    let key = [0u8; 32];
    let mut cipher = CipherState::new(key);

    assert_eq!(cipher.nonce(), 0);

    let _ = cipher.encrypt(b"test").unwrap();
    assert_eq!(cipher.nonce(), 1);

    let _ = cipher.encrypt(b"test").unwrap();
    assert_eq!(cipher.nonce(), 2);
}

#[test]
fn test_session_remote_static() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut init = HandshakeState::new_initiator(keypair1, keypair2.public_key());
    init.set_local_epoch(generate_epoch());
    let mut resp = HandshakeState::new_responder(keypair2);
    resp.set_local_epoch(generate_epoch());

    let msg1 = init.write_message_1().unwrap();
    resp.read_message_1(&msg1).unwrap();
    let msg2 = resp.write_message_2().unwrap();
    init.read_message_2(&msg2).unwrap();

    let session1 = init.into_session().unwrap();
    let session2 = resp.into_session().unwrap();

    // Each session should know the other's static key
    assert_eq!(session1.remote_static(), &keypair2.public_key());
    assert_eq!(session2.remote_static(), &keypair1.public_key());
}

#[test]
fn test_message_sizes() {
    // Verify our size constants are correct
    assert_eq!(EPOCH_SIZE, 8);
    assert_eq!(EPOCH_ENCRYPTED_SIZE, 8 + 16); // epoch + AEAD tag
    assert_eq!(HANDSHAKE_MSG1_SIZE, 33 + 33 + 16 + 24); // e + encrypted_s + encrypted_epoch
    assert_eq!(HANDSHAKE_MSG2_SIZE, 33 + 24); // e + encrypted_epoch
}

#[test]
fn test_responder_identity_discovery() {
    // This test verifies the key IK property: responder learns initiator's identity
    let initiator_keypair = generate_keypair();
    let responder_keypair = generate_keypair();

    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(generate_epoch());

    // Before message 1: responder has no idea who's connecting
    assert!(responder.remote_static().is_none());

    let mut initiator =
        HandshakeState::new_initiator(initiator_keypair, responder_keypair.public_key());
    initiator.set_local_epoch(generate_epoch());
    let msg1 = initiator.write_message_1().unwrap();

    // After processing message 1: responder knows initiator's identity
    responder.read_message_1(&msg1).unwrap();
    let discovered_initiator = responder.remote_static().unwrap();
    assert_eq!(discovered_initiator, &initiator_keypair.public_key());

    // The discovered key can be used to look up peer config, verify against allow-list, etc.
}

// ===== ReplayWindow Tests =====
