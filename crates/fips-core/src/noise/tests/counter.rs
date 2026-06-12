use super::*;

#[test]
fn test_encrypt_with_counter_no_aad_roundtrip() {
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

    let sender = init.into_session().unwrap();
    let mut receiver = resp.into_session().unwrap();

    // Off-task encrypt path: dispatcher pre-assigns counter 0, hands cipher
    // clone + counter to a worker, worker produces ciphertext using ring's
    // in-place seal — same code the future pipelined dispatcher will run.
    let send_cipher = sender.send_cipher_clone().unwrap();
    let counter = 0u64;
    let plaintext = b"off-task encrypt";
    let nonce = CipherState::counter_to_nonce(counter);
    let mut buf = plaintext.to_vec();
    send_cipher
        .seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut buf)
        .expect("worker AEAD encrypt");
    let ciphertext = buf;

    // Receiver decrypts via its normal replay-window path.
    let decrypted = receiver
        .decrypt_with_replay_check(&ciphertext, counter)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_with_counter_matches_internal_counter() {
    // Same key, same counter → identical ciphertext. Proves
    // encrypt_with_counter is a faithful &self mirror of encrypt().
    let key = [0x42u8; 32];
    let mut a = CipherState::new(key);
    let b = CipherState::new(key);

    let plaintext = b"same key, same counter, same output";

    // Internal-counter path consumes counter 0.
    let counter_a = a.nonce();
    let ct_a = a.encrypt(plaintext).unwrap();

    // Explicit-counter path uses 0 too.
    let ct_b = b.encrypt_with_counter(plaintext, counter_a).unwrap();

    assert_eq!(
        ct_a, ct_b,
        "explicit-counter encrypt must be byte-identical"
    );

    // And b's nonce stayed at 0 (no internal mutation).
    assert_eq!(b.nonce(), 0);
}

#[test]
fn test_encrypt_with_counter_and_aad_roundtrip_via_session() {
    // Pipelined encrypt: take_send_counter on session, then
    // encrypt_with_counter_and_aad on a clone. Receiver decrypts with
    // matching counter+AAD via its existing path.
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

    let mut sender = init.into_session().unwrap();
    let mut receiver = resp.into_session().unwrap();

    let aad = b"outer header bytes";
    let plaintext = b"pipelined send";

    // Dispatcher: reserve counter under sender's &mut.
    let counter = sender.take_send_counter().unwrap();
    assert_eq!(counter, 0);
    assert_eq!(sender.send_nonce(), 1, "counter reserved → nonce advanced");

    // Worker: clone + AEAD on cloned cipher, no further session mutation.
    let cipher = sender.send_cipher_clone().unwrap();
    let nonce = CipherState::counter_to_nonce(counter);
    let mut buf = plaintext.to_vec();
    cipher
        .seal_in_place_append_tag(nonce, ring::aead::Aad::from(aad), &mut buf)
        .unwrap();
    let ciphertext = buf;

    // Receiver: existing replay-window path with matching AAD.
    let decrypted = receiver
        .decrypt_with_replay_check_and_aad(&ciphertext, counter, aad)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_pipelined_send_counter_reservation_is_single_owner() {
    // Dataplane send workers may own cloned AEAD keys, but the session remains
    // the sole owner of counter sequencing until a later shard explicitly moves
    // that state. Reserved counters must be unique, and clone-side AEAD must not
    // advance or reuse the session's next counter.
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

    let mut sender = init.into_session().unwrap();
    let mut receiver = resp.into_session().unwrap();
    let aad = b"reserved-counter header";

    let first_counter = sender.take_send_counter().unwrap();
    let second_counter = sender.take_send_counter().unwrap();
    assert_eq!(first_counter, 0);
    assert_eq!(second_counter, 1);
    assert_eq!(
        sender.current_send_counter(),
        2,
        "only the coordinator-owned reservation path advances the session counter"
    );

    let cipher = sender.send_cipher_clone().unwrap();
    let mut first = b"first reserved packet".to_vec();
    cipher
        .seal_in_place_append_tag(
            CipherState::counter_to_nonce(first_counter),
            ring::aead::Aad::from(aad),
            &mut first,
        )
        .unwrap();
    let mut second = b"second reserved packet".to_vec();
    cipher
        .seal_in_place_append_tag(
            CipherState::counter_to_nonce(second_counter),
            ring::aead::Aad::from(aad),
            &mut second,
        )
        .unwrap();

    assert_eq!(
        sender.current_send_counter(),
        2,
        "worker-side cloned cipher use must not mutate session counter ownership"
    );
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(&first, first_counter, aad)
            .unwrap(),
        b"first reserved packet"
    );
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(&second, second_counter, aad)
            .unwrap(),
        b"second reserved packet"
    );

    let third_counter = sender.current_send_counter();
    let third = sender
        .encrypt_with_aad(b"inline packet after workers", aad)
        .unwrap();
    assert_eq!(third_counter, 2);
    assert_eq!(sender.current_send_counter(), 3);
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(&third, third_counter, aad)
            .unwrap(),
        b"inline packet after workers"
    );
}

#[test]
fn test_recv_cipher_clone_matches_decrypt_with_counter_and_aad() {
    // Off-task decrypt: worker holds recv_cipher_clone + counter + aad,
    // computes the AEAD on its own thread, returns plaintext to dispatcher
    // which then calls accept_replay. This test simulates that flow.
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

    let mut sender = init.into_session().unwrap();
    let mut receiver = resp.into_session().unwrap();

    let aad = b"AAD-bound transport header";
    let plaintext = b"off-task decrypt";

    // Sender produces ciphertext (any path).
    let counter = sender.current_send_counter();
    let ciphertext = sender.encrypt_with_aad(plaintext, aad).unwrap();

    // Dispatcher's cheap replay check passes.
    assert!(receiver.check_replay(counter).is_ok());

    // Worker decrypts via cloned cipher (no session lock held). ring's
    // open_in_place mutates the buffer in place and returns the plaintext
    // sub-slice; the dispatcher would normally take ownership of that
    // subslice and forward it to the link-message handler.
    let cipher = receiver.recv_cipher_clone().unwrap();
    let nonce = CipherState::counter_to_nonce(counter);
    let mut buf = ciphertext.clone();
    let worker_plaintext = cipher
        .open_in_place(nonce, ring::aead::Aad::from(aad), &mut buf)
        .unwrap()
        .to_vec();
    assert_eq!(worker_plaintext, plaintext);

    // Dispatcher accepts counter into replay window only after worker success.
    receiver.accept_replay(counter);

    // Replay should now be detected on the same counter.
    assert!(receiver.check_replay(counter).is_err());
}

// `counter_to_nonce` is a private associated fn on CipherState in the parent
// module; the tests submodule inherits visibility, so we can use it directly
// rather than duplicating the byte layout here.
