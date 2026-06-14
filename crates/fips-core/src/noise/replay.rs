use super::REPLAY_WINDOW_SIZE;
use std::fmt;

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
    /// Ring bitmap tracking which counters in the current window have been seen.
    /// Bit `counter % REPLAY_WINDOW_SIZE` belongs to that absolute counter while
    /// it is within `[highest + 1 - REPLAY_WINDOW_SIZE, highest]`.
    bitmap: [u64; REPLAY_WINDOW_SIZE / 64],
}

impl ReplayWindow {
    /// Create a new replay window.
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; REPLAY_WINDOW_SIZE / 64],
        }
    }

    /// Check if a counter is valid (not replayed, not too old).
    ///
    /// Returns true if the counter is acceptable, false if it should be rejected.
    /// Does NOT update the window - call `accept` after successful decryption.
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.highest {
            // New highest - always acceptable
            return true;
        }

        // Counter is <= highest, check if it's within the window
        let diff = self.highest - counter;
        if diff as usize >= REPLAY_WINDOW_SIZE {
            // Too old (outside window)
            return false;
        }

        let (word_idx, mask) = Self::bit_position(counter);
        (self.bitmap[word_idx] & mask) == 0
    }

    /// Accept a counter into the window.
    ///
    /// Call this only after successful decryption to prevent
    /// DoS attacks that exhaust the window.
    pub fn accept(&mut self, counter: u64) {
        if counter > self.highest {
            // Advance the logical window. The common in-order packet path only
            // clears one recycled bit instead of shifting the whole bitmap.
            let shift = counter - self.highest;
            if shift as usize >= REPLAY_WINDOW_SIZE {
                self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            } else {
                self.clear_counter_range(self.highest + 1, counter);
            }
            self.highest = counter;
        }

        let (word_idx, mask) = Self::bit_position(counter);
        self.bitmap[word_idx] |= mask;
    }

    fn clear_counter_range(&mut self, start: u64, end: u64) {
        debug_assert!(start <= end);
        for counter in start..=end {
            let (word_idx, mask) = Self::bit_position(counter);
            self.bitmap[word_idx] &= !mask;
        }
    }

    #[inline]
    fn bit_position(counter: u64) -> (usize, u64) {
        let bit = (counter as usize) % REPLAY_WINDOW_SIZE;
        (bit / 64, 1u64 << (bit % 64))
    }

    /// Get the highest counter seen.
    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// Reset the window (use when rekeying).
    pub fn reset(&mut self) {
        self.highest = 0;
        self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
    }
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
