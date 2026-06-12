use super::*;

#[test]
fn test_xk_invalid_msg1_size() {
    let keypair = generate_keypair();
    let mut responder = HandshakeState::new_xk_responder(keypair);
    responder.set_local_epoch(generate_epoch());

    // Wrong size (IK msg1 size instead of XK)
    assert!(
        responder
            .read_xk_message_1(&[0u8; HANDSHAKE_MSG1_SIZE])
            .is_err()
    );
    // Too short
    assert!(responder.read_xk_message_1(&[0u8; 10]).is_err());
}

#[test]
fn test_xk_invalid_msg3_size() {
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    let mut initiator = HandshakeState::new_xk_initiator(keypair1, keypair2.public_key());
    initiator.set_local_epoch(generate_epoch());
    let mut responder = HandshakeState::new_xk_responder(keypair2);
    responder.set_local_epoch(generate_epoch());

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let _msg2 = responder.write_xk_message_2().unwrap();

    // Responder is now in Message2Done, try wrong-size msg3
    assert!(responder.read_xk_message_3(&[0u8; 10]).is_err());
    assert!(
        responder
            .read_xk_message_3(&[0u8; XK_HANDSHAKE_MSG3_SIZE + 1])
            .is_err()
    );
}

// ===== Off-task encrypt/decrypt API parity =====
//
// `encrypt_with_counter[_and_aad]` is the &self counterpart to the existing
// internal-counter `encrypt[_with_aad]`. These tests verify that:
//   1. A ciphertext produced via the off-task path round-trips through the
//      receiver's existing replay-window decrypt path.
//   2. For the same key + same counter, both encrypt paths produce
//      identical ciphertext.
//   3. `cipher_clone()` + `decrypt_with_counter_and_aad` on the clone
//      matches an in-place decrypt — i.e. workers holding a clone see
//      the exact same AEAD outcome as the owning task would.
//   4. `take_send_counter` + `encrypt_with_counter_and_aad` is equivalent
//      to the internal-counter `encrypt_with_aad`.
