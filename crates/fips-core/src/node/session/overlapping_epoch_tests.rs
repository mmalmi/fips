use super::*;

use crate::node::session_wire::FSP_INNER_HEADER_SIZE;
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

fn receive_sync(counter: u64, slot: EpochSlot, received_k_bit: bool) -> FspReceiveSync {
    FspReceiveSync {
        counter,
        slot,
        received_k_bit,
        timestamp: 0x0102_0304,
        plaintext_len: FSP_INNER_HEADER_SIZE + 16,
        ce_flag: false,
        path_mtu: 1_280,
        spin_bit: false,
    }
}

#[test]
fn apply_fsp_receive_sync_current_advances_replay_and_inbound_state() {
    let (_send, recv) = xk_pair(1, 2);
    let mut entry = entry_with_current(recv);
    entry.record_decrypt_failure();

    let k_bit = entry.current_k_bit();
    let applied = entry.apply_fsp_receive_sync_result(
        receive_sync(7, EpochSlot::Current, k_bit),
        2_000,
        Instant::now(),
    );

    assert!(applied.is_applied());
    assert!(!applied.refresh_worker_session());
    assert_eq!(entry.current_highest_counter(), Some(7));
    assert_eq!(entry.consecutive_decrypt_failures(), 0);
    assert_eq!(entry.last_inbound_frame_ms(), 2_000);
}

#[test]
fn apply_fsp_receive_sync_rejects_seen_counter() {
    let (_send, recv) = xk_pair(1, 2);
    let mut entry = entry_with_current(recv);
    let k_bit = entry.current_k_bit();

    assert!(
        entry
            .apply_fsp_receive_sync_result(
                receive_sync(4, EpochSlot::Current, k_bit),
                2_000,
                Instant::now(),
            )
            .is_applied()
    );
    assert!(
        !entry
            .apply_fsp_receive_sync_result(
                receive_sync(4, EpochSlot::Current, k_bit),
                2_100,
                Instant::now(),
            )
            .is_applied(),
        "rx-loop mirror must not dispatch a worker-authenticated replay"
    );
}

#[test]
fn apply_fsp_receive_sync_pending_promotes_epoch_and_refreshes_worker() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (_pending_send, pending_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(pending_recv);

    let applied = entry.apply_fsp_receive_sync_result(
        receive_sync(0, EpochSlot::Pending, !k_before),
        2_000,
        Instant::now(),
    );

    assert!(applied.is_applied());
    assert!(applied.refresh_worker_session());
    assert!(entry.pending_new_session().is_none());
    assert_ne!(entry.current_k_bit(), k_before);
    assert!(entry.previous_highest_counter().is_some());
}

#[test]
fn apply_fsp_receive_sync_previous_refreshes_drain_progress() {
    const DRAIN_MS: u64 = 10_000;
    let cutover_ms = 1_000;

    let (_old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(new_recv);
    entry.set_previous_session_for_test(old_recv, cutover_ms);
    assert!(entry.is_draining());

    let old_k_bit = !entry.current_k_bit();
    for (counter, now_ms) in [(0, 5_000), (1, 15_000), (2, 25_000)] {
        let applied = entry.apply_fsp_receive_sync_result(
            receive_sync(counter, EpochSlot::Previous, old_k_bit),
            now_ms,
            Instant::now(),
        );
        assert!(applied.is_applied());
        assert!(
            !entry.drain_expired(now_ms, DRAIN_MS),
            "previous slot must not be retired while peer keeps using it"
        );
        assert_eq!(entry.previous_highest_counter(), Some(counter));
    }

    assert!(!entry.drain_expired(34_999, DRAIN_MS));
    assert!(entry.drain_expired(35_000, DRAIN_MS));
}

#[test]
fn msg3_retransmit_stops_on_peer_new_epoch_confirmed() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (_pending_send, pending_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    entry.set_pending_session(pending_recv);
    entry.set_rekey_completed_ms(1_000);
    entry.set_rekey_msg3_payload(vec![0xAB; 73], 1_500);

    assert!(entry.cutover_to_new_session(2_000));
    assert!(entry.rekey_msg3_payload().is_some());
    assert!(!entry.peer_new_epoch_confirmed());

    let k_now = entry.current_k_bit();
    assert!(
        entry
            .apply_fsp_receive_sync_result(
                receive_sync(0, EpochSlot::Current, k_now),
                2_500,
                Instant::now(),
            )
            .is_applied()
    );
    assert!(entry.peer_new_epoch_confirmed());
    assert!(entry.rekey_msg3_payload().is_none());
}

#[test]
fn msg3_retransmit_budget_exhaustion_abandons_cleanly() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (_pending_send, pending_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    entry.set_pending_session(pending_recv);
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
fn pending_sync_without_pending_session_is_stale_until_session_arrives() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (_pending_send, pending_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(cur_recv);

    assert!(
        !entry
            .apply_fsp_receive_sync_result(
                receive_sync(0, EpochSlot::Pending, true),
                2_100,
                Instant::now(),
            )
            .is_applied(),
        "rx loop cannot mirror a pending-epoch worker result before the owner has the pending session"
    );

    entry.set_pending_session(pending_recv);
    assert!(
        entry
            .apply_fsp_receive_sync_result(
                receive_sync(0, EpochSlot::Pending, true),
                2_300,
                Instant::now(),
            )
            .is_applied()
    );
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
