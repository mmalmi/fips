use super::*;

use crate::node::session_wire::{FSP_FLAG_K, build_fsp_header};
use secp256k1::{Keypair, Secp256k1, SecretKey};

fn keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let mut bytes = [1u8; 32];
    bytes[0] = seed;
    let sk = SecretKey::from_slice(&bytes).expect("valid secret key");
    Keypair::from_secret_key(&secp, &sk)
}

fn xk_pair(init_seed: u8, resp_seed: u8) -> (NoiseSession, NoiseSession) {
    let init_kp = keypair(init_seed);
    let resp_kp = keypair(resp_seed);
    let mut initiator = HandshakeState::new_xk_initiator(init_kp, resp_kp.public_key());
    initiator.set_local_epoch([0xA1, 0xB2, 0xC3, 0xD4, 0x11, 0x22, 0x33, 0x44]);
    let mut responder = HandshakeState::new_xk_responder(resp_kp);
    responder.set_local_epoch([0xD4, 0xC3, 0xB2, 0xA1, 0x44, 0x33, 0x22, 0x11]);

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator.write_xk_message_3().unwrap();
    responder.read_xk_message_3(&msg3).unwrap();

    (
        initiator.into_session().unwrap(),
        responder.into_session().unwrap(),
    )
}

fn seal(sender: &mut NoiseSession, plaintext: &[u8], k_bit: bool) -> (Vec<u8>, u64, [u8; 12]) {
    let counter = sender.current_send_counter();
    let flags = if k_bit { FSP_FLAG_K } else { 0 };
    let header = build_fsp_header(counter, flags, plaintext.len() as u16);
    let ciphertext = sender.encrypt_with_aad(plaintext, &header).unwrap();
    (ciphertext, counter, header)
}

fn entry_with_current(session: NoiseSession) -> SessionEntry {
    let addr = NodeAddr::from_bytes([7u8; 16]);
    let pubkey = keypair(99).public_key();
    let mut entry = SessionEntry::new(
        addr,
        pubkey,
        EndToEndState::Established(session),
        1_000,
        true,
    );
    entry.mark_established(1_000);
    entry
}

#[test]
fn open_fsp_established_frame_picks_current() {
    let (mut cur_send, cur_recv) = xk_pair(1, 2);
    let (_p_send, p_recv) = xk_pair(3, 4);
    let (_o_send, o_recv) = xk_pair(5, 6);

    let mut entry = entry_with_current(cur_recv);
    entry.set_pending_session(p_recv);
    entry.set_previous_session_for_test(o_recv, 1_000);

    let (ct, counter, hdr) = seal(&mut cur_send, b"steady-state", false);
    let (pt, slot) = entry
        .open_fsp_established_frame(&ct, counter, &hdr, false, 2_000)
        .expect("current frame must decrypt");

    assert_eq!(pt, b"steady-state");
    assert_eq!(slot, EpochSlot::Current);
    assert_eq!(entry.pending_highest_counter(), Some(0));
    assert_eq!(entry.previous_highest_counter(), Some(0));
}

#[test]
fn open_fsp_established_frame_picks_pending_and_promotes() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(p_recv);

    let (ct, counter, hdr) = seal(&mut p_send, b"new-epoch", !k_before);
    let (pt, slot) = entry
        .open_fsp_established_frame(&ct, counter, &hdr, !k_before, 2_000)
        .expect("pending frame must decrypt");
    assert_eq!(pt, b"new-epoch");
    assert_eq!(slot, EpochSlot::Pending);

    entry.handle_peer_kbit_flip(2_000);
    assert!(entry.pending_new_session().is_none());
    assert!(entry.previous_highest_counter().is_some());
    assert_ne!(entry.current_k_bit(), k_before);
}

#[test]
fn open_fsp_established_frame_picks_previous_during_drain() {
    let (mut old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(new_recv);
    entry.set_previous_session_for_test(old_recv, 1_500);
    let k_after = entry.current_k_bit();

    let (ct, counter, hdr) = seal(&mut old_send, b"old-straggler", !k_after);
    let (pt, slot) = entry
        .open_fsp_established_frame(&ct, counter, &hdr, !k_after, 3_000)
        .expect("previous frame must decrypt");

    assert_eq!(pt, b"old-straggler");
    assert_eq!(slot, EpochSlot::Previous);
    assert_eq!(entry.current_k_bit(), k_after);
    assert!(entry.is_draining());
}

#[test]
fn open_fsp_established_frame_accepts_reordered_old_after_cutover() {
    let (mut cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(p_recv);

    let (ct_new, c_new, hdr_new) = seal(&mut p_send, b"after-cutover", !k_before);
    let (_pt, slot) = entry
        .open_fsp_established_frame(&ct_new, c_new, &hdr_new, !k_before, 2_000)
        .unwrap();
    assert_eq!(slot, EpochSlot::Pending);
    entry.handle_peer_kbit_flip(2_000);

    let (ct_old, c_old, hdr_old) = seal(&mut cur_send, b"reordered-old", k_before);
    let (pt, slot) = entry
        .open_fsp_established_frame(&ct_old, c_old, &hdr_old, k_before, 2_500)
        .expect("reordered old-epoch frame must still decrypt");
    assert_eq!(pt, b"reordered-old");
    assert_eq!(slot, EpochSlot::Previous);
}

#[test]
fn open_fsp_established_frame_replay_is_per_slot() {
    let (mut cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(p_recv);

    let (ct, counter, hdr) = seal(&mut cur_send, b"first", k_before);
    let (_pt, slot) = entry
        .open_fsp_established_frame(&ct, counter, &hdr, k_before, 2_000)
        .unwrap();
    assert_eq!(slot, EpochSlot::Current);

    assert!(
        entry
            .open_fsp_established_frame(&ct, counter, &hdr, k_before, 2_100)
            .is_err(),
        "a genuine replay must be rejected by every slot"
    );
    assert_eq!(entry.pending_highest_counter(), Some(0));

    let (ct_p, c_p, hdr_p) = seal(&mut p_send, b"pending-c0", !k_before);
    assert_eq!(c_p, 0);
    let (pt, slot) = entry
        .open_fsp_established_frame(&ct_p, c_p, &hdr_p, !k_before, 2_200)
        .expect("pending frame must decrypt despite current replay overlap");
    assert_eq!(pt, b"pending-c0");
    assert_eq!(slot, EpochSlot::Pending);
}

#[test]
fn apply_fsp_receive_sync_rejects_rx_loop_seen_counter() {
    let (mut cur_send, cur_recv) = xk_pair(1, 2);
    let mut entry = entry_with_current(cur_recv);
    let k_bit = entry.current_k_bit();
    let (ct, counter, hdr) = seal(&mut cur_send, b"slow-path-first", k_bit);

    entry
        .open_fsp_established_frame(&ct, counter, &hdr, k_bit, 2_000)
        .expect("slow path receive should consume replay counter");

    let sync = FspReceiveSync {
        counter,
        slot: EpochSlot::Current,
        received_k_bit: k_bit,
        timestamp: 0x0102_0304,
        plaintext_len: b"slow-path-first".len(),
        ce_flag: false,
        path_mtu: 1_280,
        spin_bit: false,
    };

    assert!(
        !entry.apply_fsp_receive_sync(sync, 2_100, Instant::now()),
        "rx-loop mirror must not dispatch a worker-authenticated replay"
    );
}

#[test]
fn open_fsp_established_frame_failed_slot_leaves_replay_window_intact() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);
    let (_o_send, o_recv) = xk_pair(5, 6);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(p_recv);
    entry.set_previous_session_for_test(o_recv, 1_000);

    for _ in 0..4 {
        let _ = seal(&mut p_send, b"warmup", !k_before);
    }
    let (ct, counter, hdr) = seal(&mut p_send, b"pending-hit", !k_before);
    assert_eq!(counter, 4);

    let (_pt, slot) = entry
        .open_fsp_established_frame(&ct, counter, &hdr, false, 2_000)
        .expect("pending frame must decrypt");
    assert_eq!(slot, EpochSlot::Pending);

    assert_eq!(entry.current_highest_counter(), Some(0));
    assert_eq!(entry.previous_highest_counter(), Some(0));
    assert_eq!(entry.pending_highest_counter(), Some(4));
}

#[test]
fn open_fsp_established_frame_failed_all_epochs_does_not_consume_replay() {
    let (mut cur_send, cur_recv) = xk_pair(1, 2);
    let (_p_send, p_recv) = xk_pair(3, 4);
    let (_o_send, o_recv) = xk_pair(5, 6);

    let mut entry = entry_with_current(cur_recv);
    let k_bit = entry.current_k_bit();
    entry.set_pending_session(p_recv);
    entry.set_previous_session_for_test(o_recv, 1_000);

    for _ in 0..3 {
        let _ = seal(&mut cur_send, b"warmup", k_bit);
    }
    let (ciphertext, counter, header) = seal(&mut cur_send, b"current-after-forgery", k_bit);
    assert_eq!(counter, 3);

    let mut forged = ciphertext.clone();
    let last = forged.last_mut().expect("ciphertext has an AEAD tag");
    *last ^= 0x55;

    assert_eq!(
        entry.open_fsp_established_frame(&forged, counter, &header, k_bit, 2_000),
        Err(FspOpenError::NoLiveEpochAccepted),
        "forged ciphertext must fail without being accepted into any replay window"
    );
    assert_eq!(entry.current_highest_counter(), Some(0));
    assert_eq!(entry.pending_highest_counter(), Some(0));
    assert_eq!(entry.previous_highest_counter(), Some(0));

    let (plaintext, slot) = entry
        .open_fsp_established_frame(&ciphertext, counter, &header, k_bit, 2_100)
        .expect("valid frame must still open after forged failure");
    assert_eq!(plaintext, b"current-after-forgery");
    assert_eq!(slot, EpochSlot::Current);
    assert_eq!(entry.current_highest_counter(), Some(counter));
    assert_eq!(entry.pending_highest_counter(), Some(0));
    assert_eq!(entry.previous_highest_counter(), Some(0));

    assert!(
        entry
            .open_fsp_established_frame(&ciphertext, counter, &header, k_bit, 2_200)
            .is_err(),
        "the valid frame is replay-protected after successful open"
    );
}

#[cfg(unix)]
#[test]
fn reserve_fsp_worker_send_owns_counter_header_and_cipher() {
    use ring::aead::Aad;

    let (send_session, mut recv_session) = xk_pair(1, 2);
    let mut entry = entry_with_current(send_session);
    let flags = FSP_FLAG_K;
    let plaintext = b"worker-sealed-fsp-frame";

    let reservation = entry
        .reserve_fsp_worker_send(flags, plaintext.len() as u16)
        .expect("counter reservation should succeed")
        .expect("established session should expose a send cipher");

    assert_eq!(reservation.counter, 0);
    assert_eq!(
        entry.send_counter(),
        1,
        "reservation is the only session mutation before worker dispatch"
    );
    assert_eq!(
        reservation.header,
        build_fsp_header(reservation.counter, flags, plaintext.len() as u16)
    );

    let mut ciphertext = plaintext.to_vec();
    reservation
        .cipher
        .seal_in_place_append_tag(
            crate::noise::CipherState::counter_to_nonce(reservation.counter),
            Aad::from(&reservation.header),
            &mut ciphertext,
        )
        .expect("worker-style FSP seal should succeed");
    assert_eq!(
        entry.send_counter(),
        1,
        "worker cipher use must not mutate the owning session"
    );
    assert_eq!(
        recv_session
            .decrypt_with_replay_check_and_aad(
                &ciphertext,
                reservation.counter,
                &reservation.header,
            )
            .expect("receiver should accept worker-sealed FSP frame"),
        plaintext
    );

    let next = entry
        .reserve_fsp_worker_send(flags, plaintext.len() as u16)
        .expect("second counter reservation should succeed")
        .expect("established session should still expose a send cipher");
    assert_eq!(next.counter, 1);
    assert_eq!(
        next.header,
        build_fsp_header(next.counter, flags, plaintext.len() as u16)
    );
}

#[test]
fn msg3_retransmit_stops_on_peer_new_epoch_confirmed() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    entry.set_pending_session(p_recv);
    entry.set_rekey_completed_ms(1_000);
    entry.set_rekey_msg3_payload(vec![0xAB; 73], 1_500);

    assert!(entry.cutover_to_new_session(2_000));
    assert!(entry.rekey_msg3_payload().is_some());
    assert!(!entry.peer_new_epoch_confirmed());

    let k_now = entry.current_k_bit();
    let (ct, counter, hdr) = seal(&mut p_send, b"peer-on-new-epoch", k_now);
    let (_pt, slot) = entry
        .open_fsp_established_frame(&ct, counter, &hdr, k_now, 2_500)
        .unwrap();
    assert_eq!(slot, EpochSlot::Current);
    assert!(entry.rekey_msg3_payload().is_some() && entry.pending_new_session().is_none());
    entry.confirm_peer_new_epoch();
    assert!(entry.peer_new_epoch_confirmed());
    assert!(entry.rekey_msg3_payload().is_none());
}

#[test]
fn msg3_retransmit_budget_exhaustion_abandons_cleanly() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (_p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    entry.set_pending_session(p_recv);
    entry.set_rekey_completed_ms(1_000);
    entry.set_rekey_msg3_payload(vec![0xCD; 73], 1_500);

    let max_resends = 8;
    for i in 0..max_resends {
        entry.record_rekey_msg3_resend(2_000 + i as u64 * 100);
    }
    assert_eq!(entry.rekey_msg3_resend_count(), max_resends);

    entry.abandon_rekey();
    assert!(entry.rekey_msg3_payload().is_none());
    assert!(entry.pending_new_session().is_none());
    assert!(!entry.has_rekey_in_progress());
    assert!(entry.is_established());
    assert!(!entry.peer_new_epoch_confirmed());
}

#[test]
fn initiator_cutover_keeps_responder_old_epoch_decryptable() {
    let (old_a, old_b) = xk_pair(1, 2);
    let (new_a, mut new_b) = xk_pair(3, 4);

    let mut a = entry_with_current(old_a);
    a.set_rekey_completed_ms(1_000);
    a.set_rekey_msg3_payload(vec![0xEE; 73], 1_500);
    a.set_pending_session(new_a);
    assert!(a.cutover_to_new_session(2_000));
    assert!(a.rekey_msg3_payload().is_some());

    let mut b = entry_with_current(old_b);

    let (ct_new, c_new, hdr_new) = seal(&mut new_b, b"new-from-a", true);
    assert!(
        b.open_fsp_established_frame(&ct_new, c_new, &hdr_new, true, 2_100)
            .is_err(),
        "responder without msg3 drops the new-epoch frame cleanly"
    );

    let (ct_old, c_old, hdr_old) = {
        let b_old = b.current_noise_session_mut().unwrap();
        seal(b_old, b"old-from-b", false)
    };
    let (pt, slot) = a
        .open_fsp_established_frame(&ct_old, c_old, &hdr_old, false, 2_200)
        .expect("initiator must still decrypt the responder's old-epoch frame");
    assert_eq!(pt, b"old-from-b");
    assert_eq!(slot, EpochSlot::Previous);

    let (new_a2, mut new_b2) = xk_pair(3, 4);
    b.set_pending_session(new_a2);
    let (ct_new2, c_new2, hdr_new2) = seal(&mut new_b2, b"new-from-a-2", true);
    let (pt, slot) = b
        .open_fsp_established_frame(&ct_new2, c_new2, &hdr_new2, true, 2_300)
        .expect("responder must decrypt new-epoch frame once pending is installed");
    assert_eq!(pt, b"new-from-a-2");
    assert_eq!(slot, EpochSlot::Pending);
}

#[test]
fn drain_expiry_is_peer_progress_aware() {
    const DRAIN_MS: u64 = 10_000;
    let cutover_ms = 1_000;

    let (mut old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(old_recv);
    entry.set_pending_session(new_recv);
    assert!(entry.cutover_to_new_session(cutover_ms));
    assert!(entry.is_draining());

    let k_old = !entry.current_k_bit();
    for &t in &[5_000u64, 15_000, 25_000] {
        let (ct, counter, hdr) = seal(&mut old_send, b"still-old-epoch", k_old);
        let (_pt, slot) = entry
            .open_fsp_established_frame(&ct, counter, &hdr, k_old, t)
            .expect("old-epoch frame must still decrypt while peer uses it");
        assert_eq!(slot, EpochSlot::Previous);
        assert!(
            !entry.drain_expired(t, DRAIN_MS),
            "previous slot must not be retired while peer keeps using it"
        );
        assert!(entry.previous_highest_counter().is_some());
    }

    assert!(!entry.drain_expired(34_999, DRAIN_MS));
    assert!(entry.drain_expired(35_000, DRAIN_MS));

    entry.complete_drain();
    assert!(entry.previous_highest_counter().is_none());
    assert!(!entry.is_draining());
}

#[test]
fn drain_expiry_unaffected_when_peer_off_old_epoch() {
    const DRAIN_MS: u64 = 10_000;
    let cutover_ms = 1_000;

    let (_old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(old_recv);
    entry.set_pending_session(new_recv);
    assert!(entry.cutover_to_new_session(cutover_ms));

    assert!(!entry.drain_expired(cutover_ms + DRAIN_MS - 1, DRAIN_MS));
    assert!(entry.drain_expired(cutover_ms + DRAIN_MS, DRAIN_MS));
}
