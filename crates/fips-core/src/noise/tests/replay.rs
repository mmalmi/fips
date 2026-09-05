use super::*;

#[test]
fn test_replay_window_basic() {
    let mut window = ReplayWindow::new();

    // First packet is always acceptable
    assert_eq!(window.rejection_reason(0), None);
    assert!(window.check(0));
    window.accept(0);
    assert_eq!(window.highest(), 0);

    // Replay of 0 should fail
    assert_eq!(window.rejection_reason(0), Some(ReplayRejection::Duplicate));
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
    assert_eq!(window.rejection_reason(5), Some(ReplayRejection::Duplicate));
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
    assert_eq!(window.rejection_reason(0), Some(ReplayRejection::TooOld));
    assert!(!window.check(0));
    assert_eq!(window.rejection_reason(50), Some(ReplayRejection::TooOld));
    assert!(!window.check(50));

    // Counters within window should work
    assert_eq!(
        window.rejection_reason(REPLAY_WINDOW_SIZE as u64 + 99),
        None
    );
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
fn test_replay_window_max_counter_does_not_wedge_the_window() {
    let mut window = ReplayWindow::new();

    window.accept(100);
    window.accept(u64::MAX);

    assert_eq!(window.highest(), 100, "reserved ceiling must be ignored");
    assert!(window.check(101), "ceiling frame wedged the replay window");
}

#[test]
fn test_replay_window_rejects_max_counter() {
    let window = ReplayWindow::new();
    assert_eq!(
        window.rejection_reason(u64::MAX),
        Some(ReplayRejection::TooOld),
        "the existing out-of-window classification covers the reserved ceiling"
    );
    assert!(!window.check(u64::MAX));
}

#[test]
fn test_replay_window_accepts_highest_sendable_counter() {
    let mut window = ReplayWindow::new();
    assert!(window.check(u64::MAX - 1));

    window.accept(u64::MAX - 1);
    assert!(!window.check(u64::MAX - 1));
}

#[test]
fn test_replay_window_ignores_expired_counter_after_split_check() {
    let mut window = ReplayWindow::new();
    assert!(window.check(0));
    window.accept(REPLAY_WINDOW_SIZE as u64);
    // Another completion can advance the window after check/decrypt.
    window.accept(0);
    assert_eq!(window.highest(), REPLAY_WINDOW_SIZE as u64);
    assert_eq!(window.rejection_reason(0), Some(ReplayRejection::TooOld));
    assert_eq!(
        window.rejection_reason(REPLAY_WINDOW_SIZE as u64),
        Some(ReplayRejection::Duplicate)
    );
}

#[test]
fn test_replay_window_matches_counter_set_across_wraps_and_u64_range() {
    let mut window = ReplayWindow::new();
    let mut seen = std::collections::HashSet::new();
    let mut highest = 0u64;
    let mut observe = |counter: u64| {
        let expected = if counter == u64::MAX
            || (counter <= highest && highest - counter >= REPLAY_WINDOW_SIZE as u64)
        {
            Some(ReplayRejection::TooOld)
        } else if seen.contains(&counter) {
            Some(ReplayRejection::Duplicate)
        } else {
            None
        };
        assert_eq!(
            window.rejection_reason(counter),
            expected,
            "counter {counter}, highest {highest}"
        );
        if expected.is_none() {
            seen.insert(counter);
            highest = highest.max(counter);
        }
        window.accept(counter);
        assert_eq!(window.highest(), highest);
    };

    for base in [0, 1u64 << 32, u64::MAX - 20_001] {
        for offset in (0..20_000).step_by(3) {
            let counter = base + offset;
            observe(counter);
            // Fill gaps out of order, revisit duplicates, and cross both
            // exact window edges and word boundaries over multiple wraps.
            for behind in [1, 63, 64, 8191, 8192, (offset * 37) % 9000] {
                observe(counter.saturating_sub(behind));
            }
        }
    }
    observe(u64::MAX - 1);
    observe(u64::MAX);
    observe(u64::MAX - 1);
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
