use super::REPLAY_WINDOW_SIZE;
use std::fmt;

// One extra word retains a full window even when its oldest and newest
// counters lie in partial words. Advancing within a word needs no clearing.
const RING_WORDS: usize = REPLAY_WINDOW_SIZE / 64 + 1;

/// Reason a counter is rejected by the replay window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayRejection {
    /// Counter is inside the replay window but its bit was already observed.
    Duplicate,
    /// Counter is behind the retained replay window, or is the reserved
    /// `u64::MAX` nonce-exhaustion sentinel outside the usable counter range.
    TooOld,
}

/// Sliding window for replay protection.
///
/// Tracks which packet counters have been received within a window of
/// REPLAY_WINDOW_SIZE. Packets with counters below the window or already
/// seen within the window are rejected.
///
/// Based on WireGuard's anti-replay mechanism (RFC 6479 style).
#[derive(Clone)]
pub struct ReplayWindow {
    /// Highest counter value seen.
    highest: u64,
    /// Counter-indexed words, reused only after their whole block expires.
    bitmap: [u64; RING_WORDS],
}

impl ReplayWindow {
    /// Create a new replay window.
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; RING_WORDS],
        }
    }

    /// Check if a counter is valid (not replayed, not too old).
    ///
    /// Returns true if the counter is acceptable, false if it should be rejected.
    /// Does NOT update the window - call `accept` after successful decryption.
    pub fn check(&self, counter: u64) -> bool {
        self.rejection_reason(counter).is_none()
    }

    /// Classify why a counter would be rejected, without updating the window.
    pub fn rejection_reason(&self, counter: u64) -> Option<ReplayRejection> {
        // Both send paths reserve the ceiling counter as the nonce-exhaustion
        // sentinel. Reuse the existing out-of-window classification to avoid a
        // source-breaking public enum variant.
        if counter == u64::MAX {
            return Some(ReplayRejection::TooOld);
        }

        if counter > self.highest {
            // New highest - always acceptable
            return None;
        }

        // Counter is <= highest, check if it's within the window
        let diff = self.highest - counter;
        if diff >= REPLAY_WINDOW_SIZE as u64 {
            // Too old (outside window)
            return Some(ReplayRejection::TooOld);
        }

        if (self.bitmap[word_index(counter)] & (1u64 << (counter % 64))) == 0 {
            None
        } else {
            Some(ReplayRejection::Duplicate)
        }
    }

    /// Accept a counter into the window.
    ///
    /// Call this only after successful decryption to prevent
    /// DoS attacks that exhaust the window. Expired counters are ignored if
    /// another packet advanced the window after the initial check.
    pub fn accept(&mut self, counter: u64) {
        // Defend callers of the split check/decrypt/accept API as well as the
        // inline decrypt path. The reserved ceiling must never pin `highest`.
        if counter == u64::MAX {
            return;
        }

        if counter > self.highest {
            let current_word = self.highest / 64;
            let next_word = counter / 64;
            if next_word - current_word >= RING_WORDS as u64 {
                self.bitmap.fill(0);
            } else {
                for word in current_word + 1..=next_word {
                    self.bitmap[(word % RING_WORDS as u64) as usize] = 0;
                }
            }
            self.highest = counter;
        } else if self.highest - counter >= REPLAY_WINDOW_SIZE as u64 {
            return;
        }
        self.bitmap[word_index(counter)] |= 1u64 << (counter % 64);
    }

    /// Get the highest counter seen.
    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// Reset the window (use when rekeying).
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

fn word_index(counter: u64) -> usize {
    ((counter / 64) % RING_WORDS as u64) as usize
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("highest", &self.highest)
            .field("window_size", &REPLAY_WINDOW_SIZE)
            .finish()
    }
}
