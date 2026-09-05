//! Routing error signal rate limiting.
//!
//! Prevents routing error floods (CoordsRequired / PathBroken) by
//! rate-limiting error signals per destination address at transit nodes.

use crate::NodeAddr;
use crate::time::{Instant, instant_now};
use std::collections::HashMap;
use std::time::Duration;

/// Hard ceiling for attacker-mintable destination keys.
const MAX_ENTRIES: usize = 4096;
const SWEEPS_PER_MAX_AGE: u32 = 8;

/// Result of checking the per-destination error-suppression interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitVerdict {
    Admit,
    /// The bounded map was full.  Emission remains allowed because the
    /// authenticated-peer budget is the actual flood bound.
    AdmitAtCapacity,
    Suppress,
}

/// Rate limiter for routing error signals (CoordsRequired / PathBroken).
///
/// Tracks the last time a routing error was sent for each destination
/// address and enforces a minimum interval to prevent floods.
pub struct RoutingErrorRateLimiter {
    /// Maps destination NodeAddr to the last time we sent an error about it.
    last_sent: HashMap<NodeAddr, Instant>,
    /// Minimum interval between error signals for the same destination.
    min_interval: Duration,
    /// Maximum age of entries before cleanup.
    max_age: Duration,
    /// Last amortized full-map expiry sweep.
    last_sweep: Instant,
    #[cfg(test)]
    sweeps: u64,
}

impl RoutingErrorRateLimiter {
    /// Create a new rate limiter.
    ///
    /// Default: max 10 errors/sec per destination (100ms interval).
    pub fn new() -> Self {
        Self::with_interval(Duration::from_millis(100))
    }

    /// Create a rate limiter with a custom minimum interval.
    pub fn with_interval(min_interval: Duration) -> Self {
        Self {
            last_sent: HashMap::new(),
            min_interval,
            max_age: Duration::from_secs(10),
            last_sweep: instant_now(),
            #[cfg(test)]
            sweeps: 0,
        }
    }

    /// Check if we should send a routing error for this destination.
    ///
    /// Returns true if enough time has passed since the last error for
    /// this destination and the bounded map can remember the admission.
    /// Updates internal state when returning true. Callers that do not apply a
    /// separate authenticated-peer budget fail closed when the map is full.
    pub fn should_send(&mut self, dest_addr: &NodeAddr) -> bool {
        self.check(dest_addr, instant_now()) == LimitVerdict::Admit
    }

    /// Check at an explicit instant and report whether the bounded map could
    /// remember this admission.
    pub fn check(&mut self, dest_addr: &NodeAddr, now: Instant) -> LimitVerdict {
        if let Some(&last) = self.last_sent.get(dest_addr)
            && now.saturating_duration_since(last) < self.min_interval
        {
            return LimitVerdict::Suppress;
        }

        if self.last_sent.len() >= MAX_ENTRIES && !self.last_sent.contains_key(dest_addr) {
            self.maybe_cleanup(now);
            if self.last_sent.len() >= MAX_ENTRIES {
                return LimitVerdict::AdmitAtCapacity;
            }
        }
        self.last_sent.insert(*dest_addr, now);
        self.maybe_cleanup(now);
        LimitVerdict::Admit
    }

    fn maybe_cleanup(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_sweep) >= self.max_age / SWEEPS_PER_MAX_AGE {
            self.cleanup(now);
        }
    }

    /// Remove entries older than max_age.
    fn cleanup(&mut self, now: Instant) {
        self.last_sweep = now;
        #[cfg(test)]
        {
            self.sweeps = self.sweeps.saturating_add(1);
        }
        self.last_sent
            .retain(|_, &mut last| now.saturating_duration_since(last) < self.max_age);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.last_sent.len()
    }

    #[cfg(test)]
    pub fn sweeps(&self) -> u64 {
        self.sweeps
    }
}

impl Default for RoutingErrorRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn minted_addr(val: u32) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&val.to_le_bytes());
        bytes[15] = 0xff;
        NodeAddr::from_bytes(bytes)
    }

    #[test]
    fn test_destination_intervals_and_independence() {
        for (mut limiter, interval) in [
            (RoutingErrorRateLimiter::new(), Duration::from_millis(100)),
            (
                RoutingErrorRateLimiter::with_interval(Duration::from_millis(500)),
                Duration::from_millis(500),
            ),
        ] {
            let now = instant_now();
            for destination in [addr(1), addr(2)] {
                assert_eq!(limiter.check(&destination, now), LimitVerdict::Admit);
                assert_eq!(limiter.check(&destination, now), LimitVerdict::Suppress);
                assert_eq!(
                    limiter.check(&destination, now + interval - Duration::from_nanos(1)),
                    LimitVerdict::Suppress
                );
                assert_eq!(
                    limiter.check(&destination, now + interval),
                    LimitVerdict::Admit
                );
            }
        }
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let mut limiter = RoutingErrorRateLimiter::new();
        assert!(limiter.should_send(&addr(1)));
        assert!(limiter.should_send(&addr(2)));
        assert_eq!(limiter.len(), 2);

        let future = Instant::now() + Duration::from_secs(11);
        limiter.cleanup(future);
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn test_cleanup_preserves_recent_entries() {
        let mut limiter = RoutingErrorRateLimiter::new();
        assert!(limiter.should_send(&addr(1)));
        assert_eq!(limiter.len(), 1);

        limiter.cleanup(Instant::now());
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn destination_capacity_verdict_and_public_admission() {
        let mut limiter = RoutingErrorRateLimiter::new();
        let now = instant_now();
        for i in 0..MAX_ENTRIES as u32 {
            assert_eq!(limiter.check(&minted_addr(i), now), LimitVerdict::Admit);
        }
        for i in MAX_ENTRIES as u32..MAX_ENTRIES as u32 + 32 {
            assert_eq!(
                limiter.check(&minted_addr(i), now),
                LimitVerdict::AdmitAtCapacity
            );
            assert!(
                !limiter.should_send(&minted_addr(i)),
                "callers without a separate peer budget must not fail open"
            );
        }
        assert_eq!(limiter.len(), MAX_ENTRIES);
    }

    #[test]
    fn destination_sweeps_are_amortized() {
        let mut limiter = RoutingErrorRateLimiter::new();
        let now = instant_now();
        for i in 0..1_000 {
            let _ = limiter.check(&minted_addr(i), now);
        }
        assert_eq!(limiter.sweeps(), 0);
    }
}
