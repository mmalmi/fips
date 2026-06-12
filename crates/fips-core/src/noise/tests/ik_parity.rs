use super::*;

#[test]
fn test_handshake_with_odd_parity_responder() {
    // Node B's secret key produces an odd-parity public key (0x03 prefix).
    // When the initiator only has the npub (x-only), PeerIdentity::pubkey_full()
    // returns even parity (0x02). The pre-message mix_hash must normalize
    // parity so both sides produce matching hash chains.
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

    // Node A (initiator) - even parity key
    let sk_a = secp256k1::SecretKey::from_slice(
        &hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap(),
    )
    .unwrap();
    let kp_a = secp256k1::Keypair::from_secret_key(&secp, &sk_a);

    // Simulate the production path: initiator gets responder's key via npub
    // (x-only -> assumed even parity)
    let assumed_even_b = xonly_b.public_key(Parity::Even);
    assert_ne!(
        assumed_even_b,
        kp_b.public_key(),
        "Even assumption should differ from actual odd key"
    );

    // Handshake using assumed-even key (as production code does)
    let mut initiator = HandshakeState::new_initiator(kp_a, assumed_even_b);
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_responder(kp_b);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();

    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    assert!(initiator.is_complete());
    assert!(responder.is_complete());

    // Verify sessions can communicate
    let mut sender = initiator.into_session().unwrap();
    let mut receiver = responder.into_session().unwrap();

    let counter = sender.current_send_counter();
    let ciphertext = sender.encrypt(b"parity test").unwrap();
    let plaintext = receiver
        .decrypt_with_replay_check(&ciphertext, counter)
        .unwrap();
    assert_eq!(plaintext, b"parity test");
}

// ===== XK Handshake Tests =====
