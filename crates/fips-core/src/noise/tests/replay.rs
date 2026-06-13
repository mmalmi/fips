use super::*;

#[test]
fn test_replay_window_basic() {
    let mut window = ReplayWindow::new();

    // First packet is always acceptable
    assert!(window.check(0));
    window.accept(0);
    assert_eq!(window.highest(), 0);

    // Replay of 0 should fail
    assert!(!window.check(0));

    // New higher counter is acceptable
    assert!(window.check(1));
    window.accept(1);
    assert_eq!(window.highest(), 1);

    // Out-of-order within window is acceptable
    // (after accepting 10, 2 is still in window)
    window.accept(10);
    assert!(window.check(5));
    window.accept(5);

    // Replay of 5 should now fail
    assert!(!window.check(5));
}

#[test]
fn test_replay_window_large_jump() {
    let mut window = ReplayWindow::new();

    // Accept counter 0
    window.accept(0);

    // Jump to a large counter
    window.accept(REPLAY_WINDOW_SIZE as u64 + 100);

    // Old counter should be outside window
    assert!(!window.check(0));
    assert!(!window.check(50));

    // Counters within window should work
    assert!(window.check(REPLAY_WINDOW_SIZE as u64 + 99));
    assert!(window.check(REPLAY_WINDOW_SIZE as u64 + 50));
}

#[test]
fn test_replay_window_boundary() {
    let mut window = ReplayWindow::new();

    // Accept at boundary
    window.accept(REPLAY_WINDOW_SIZE as u64 - 1);

    // Counter 0 should be exactly at the edge of the window
    assert!(window.check(0));
    window.accept(0);

    // Move window forward by 1
    window.accept(REPLAY_WINDOW_SIZE as u64);

    // Counter 0 is now outside the window
    assert!(!window.check(0));

    // Counter 1 is still in the window
    assert!(window.check(1));
}

#[test]
fn test_replay_window_clears_reused_ring_slots() {
    let mut window = ReplayWindow::new();

    window.accept(1);
    assert!(!window.check(1));

    let high = REPLAY_WINDOW_SIZE as u64 + 2;
    window.accept(high);

    // Counter 1 and counter REPLAY_WINDOW_SIZE + 1 share the same bitmap bit
    // in the ring representation. Advancing the window must clear that reused
    // slot so the newer in-window counter is not mistaken for a replay.
    let reused_slot_counter = REPLAY_WINDOW_SIZE as u64 + 1;
    assert!(window.check(reused_slot_counter));
    window.accept(reused_slot_counter);
    assert!(!window.check(reused_slot_counter));
}

#[test]
fn test_replay_window_matches_set_model_across_wraps() {
    use std::collections::HashSet;

    fn model_check(seen: &HashSet<u64>, highest: u64, counter: u64) -> bool {
        if counter > highest {
            return true;
        }
        highest - counter < REPLAY_WINDOW_SIZE as u64 && !seen.contains(&counter)
    }

    fn model_accept(seen: &mut HashSet<u64>, highest: &mut u64, counter: u64) {
        if counter > *highest {
            *highest = counter;
            seen.retain(|seen_counter| *highest - *seen_counter < REPLAY_WINDOW_SIZE as u64);
        }
        seen.insert(counter);
    }

    let mut window = ReplayWindow::new();
    let mut seen = HashSet::new();
    let mut highest = 0;
    let counters = [
        0,
        1,
        2,
        1000,
        20,
        REPLAY_WINDOW_SIZE as u64 - 1,
        REPLAY_WINDOW_SIZE as u64,
        100,
        REPLAY_WINDOW_SIZE as u64 + 2,
        REPLAY_WINDOW_SIZE as u64 + 1,
        (REPLAY_WINDOW_SIZE * 2) as u64 - 1,
        REPLAY_WINDOW_SIZE as u64 + 900,
        (REPLAY_WINDOW_SIZE * 2) as u64,
        (REPLAY_WINDOW_SIZE * 2) as u64 + 1,
        5000,
        7000,
        6999,
        9000,
    ];

    for counter in counters {
        assert_eq!(
            window.check(counter),
            model_check(&seen, highest, counter),
            "pre-accept check mismatch for counter {counter}"
        );
        if model_check(&seen, highest, counter) {
            window.accept(counter);
            model_accept(&mut seen, &mut highest, counter);
            assert!(
                !window.check(counter),
                "accepted counter {counter} must replay"
            );
        }

        for probe in [
            0,
            1,
            counter.saturating_sub(1),
            counter,
            counter.saturating_add(1),
            highest.saturating_sub(REPLAY_WINDOW_SIZE as u64),
            highest.saturating_sub(REPLAY_WINDOW_SIZE as u64 - 1),
            highest,
        ] {
            assert_eq!(
                window.check(probe),
                model_check(&seen, highest, probe),
                "probe check mismatch after counter {counter}, probe {probe}"
            );
        }
    }
}

#[test]
fn test_replay_window_sequential() {
    let mut window = ReplayWindow::new();

    // Accept counters 0-999 in order
    for i in 0..1000 {
        assert!(window.check(i), "Counter {} should be acceptable", i);
        window.accept(i);
    }

    // All should be marked as seen
    for i in 0..1000 {
        assert!(
            !window.check(i),
            "Counter {} should be rejected as replay",
            i
        );
    }

    assert_eq!(window.highest(), 999);
}

#[test]
fn test_replay_window_reset() {
    let mut window = ReplayWindow::new();

    window.accept(100);
    assert_eq!(window.highest(), 100);
    assert!(!window.check(100));

    window.reset();

    assert_eq!(window.highest(), 0);
    assert!(window.check(100));
}

#[test]
fn test_session_replay_protection() {
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

    // Encrypt a message
    let counter = sender.current_send_counter();
    let ciphertext = sender.encrypt(b"test message").unwrap();

    // First decryption should succeed
    let plaintext = receiver
        .decrypt_with_replay_check(&ciphertext, counter)
        .unwrap();
    assert_eq!(plaintext, b"test message");

    // Replay should fail
    let result = receiver.decrypt_with_replay_check(&ciphertext, counter);
    assert!(matches!(result, Err(NoiseError::ReplayDetected(_))));

    // Check method alone also detects replay
    assert!(receiver.check_replay(counter).is_err());
}
