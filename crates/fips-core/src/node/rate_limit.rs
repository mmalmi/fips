//! Rate Limiting for FIPS Protocol
//!
//! Provides token bucket rate limiting for protecting against DoS attacks,
//! particularly on the Noise handshake path where msg1 processing involves
//! expensive cryptographic operations.
//!
//! ## Design
//!
//! - Token bucket algorithm with configurable burst and refill rate
//! - Global rate limit (not per-source, since UDP sources are spoofable)
//! - Applied before expensive DH operations in handshake processing
//!
//! ## Default Parameters
//!
//! - Burst capacity: 100 tokens (max concurrent handshakes)
//! - Refill rate: 10 tokens/second (sustained handshake rate)
//! - This allows handling burst traffic while limiting sustained attack impact
//!
//! Msg1 from an address already associated with a live or pending link draws
//! on a separate bucket. This keeps stranger floods from consuming all rekey
//! and restart capacity, while still metering the address-based carve-out
//! because UDP source addresses can be forged. Both classes share one pending
//! ceiling, so splitting rate capacity does not inflate handshake concurrency.

use crate::NodeAddr;
use crate::time::{Instant, instant_now};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Default burst capacity (max tokens).
pub const DEFAULT_BURST_CAPACITY: u32 = 100;

/// Default refill rate (tokens per second).
pub const DEFAULT_REFILL_RATE: f64 = 10.0;

/// Token bucket rate limiter.
///
/// Uses a classic token bucket algorithm where tokens are consumed for each
/// operation and refilled at a constant rate. When tokens are exhausted,
/// operations are rate-limited until tokens refill.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Maximum number of tokens (burst capacity).
    capacity: u32,
    /// Current number of available tokens (may be fractional during refill).
    tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket with default parameters.
    ///
    /// - Burst capacity: 100 tokens
    /// - Refill rate: 10 tokens/second
    pub fn new() -> Self {
        Self::with_params(DEFAULT_BURST_CAPACITY, DEFAULT_REFILL_RATE)
    }

    /// Create a token bucket with custom parameters.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens (burst capacity)
    /// * `refill_rate` - Tokens added per second
    pub fn with_params(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: instant_now(),
        }
    }

    /// Try to consume one token.
    ///
    /// Returns `true` if a token was available and consumed, `false` if
    /// rate limited (no tokens available).
    pub fn try_acquire(&mut self) -> bool {
        self.try_acquire_n(1)
    }

    /// Try to consume n tokens.
    ///
    /// Returns `true` if n tokens were available and consumed, `false` if
    /// rate limited (insufficient tokens).
    pub fn try_acquire_n(&mut self, n: u32) -> bool {
        self.refill();

        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }

    /// Check if tokens are available without consuming them.
    #[cfg(test)]
    pub fn available(&mut self) -> bool {
        self.refill();
        self.tokens >= 1.0
    }

    /// Get the current number of available tokens.
    #[cfg(test)]
    pub fn tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    /// Get the capacity (max tokens).
    #[cfg(test)]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = instant_now();
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed.as_secs_f64();

        // Add tokens based on time elapsed
        self.tokens += elapsed_secs * self.refill_rate;

        // Cap at capacity
        if self.tokens > self.capacity as f64 {
            self.tokens = self.capacity as f64;
        }

        self.last_refill = now;
    }

    /// Reset to full capacity.
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.tokens = self.capacity as f64;
        self.last_refill = instant_now();
    }

    /// Time until the next token is available.
    ///
    /// Returns `Duration::ZERO` if tokens are available, otherwise the
    /// estimated time until one token will be available.
    #[cfg(test)]
    pub fn time_until_available(&mut self) -> std::time::Duration {
        self.refill();

        if self.tokens >= 1.0 {
            std::time::Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            let secs = needed / self.refill_rate;
            std::time::Duration::from_secs_f64(secs)
        }
    }
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Floor on the derived established-link refill rate, in tokens/second.
pub(in crate::node) const ESTABLISHED_RATE_FLOOR: f64 = 1.0;

/// Which rate bucket an inbound msg1 consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum Msg1Class {
    Stranger,
    EstablishedLink,
}

/// Which limiter limb refused an inbound msg1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum Msg1Refusal {
    PendingLimit,
    RateLimit,
}

impl std::fmt::Display for Msg1Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PendingLimit => "pending_limit",
            Self::RateLimit => "rate_limit",
        })
    }
}

/// A shared in-flight slot that releases itself on every return path.
///
/// The guard owns an `Arc`, not a borrow of the limiter, so it can be held
/// across awaits while `Node` continues mutating its other state.
#[must_use = "the guard must stay bound for the duration of msg1 processing"]
#[derive(Debug)]
pub(in crate::node) struct PendingHandshake {
    pending: Arc<AtomicUsize>,
}

impl Drop for PendingHandshake {
    fn drop(&mut self) {
        let _ = self
            .pending
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_sub(1)
            });
    }
}

/// Derive established-maintenance capacity from existing operator settings.
///
/// The burst admits one simultaneous maintenance msg1 per configured
/// established link or end-to-end session. The rate covers steady rekey
/// traffic plus its retransmission budget, with a floor for restarts when
/// periodic rekey is very infrequent. An unlimited population reuses the
/// stranger bucket because no configured bound exists.
pub(in crate::node) fn derive_established_bucket(
    max_established: usize,
    rekey_after_secs: u64,
    max_resends: u32,
    stranger_burst: u32,
    stranger_rate: f64,
) -> (u32, f64) {
    if max_established == 0 {
        return (stranger_burst, stranger_rate);
    }

    let burst = u32::try_from(max_established).unwrap_or(u32::MAX);
    let period = rekey_after_secs.max(1) as f64;
    let rate = (max_established as f64 / period) * (1.0 + f64::from(max_resends));
    (burst, rate.max(ESTABLISHED_RATE_FLOOR))
}

/// Rate limiter for handshake message 1 processing.
///
/// Stranger and established-link traffic have independent token buckets but
/// share one pending-handshake ceiling.
#[derive(Debug)]
pub struct HandshakeRateLimiter {
    bucket: TokenBucket,
    established: TokenBucket,
    pending: Arc<AtomicUsize>,
    max_pending: usize,
}

impl HandshakeRateLimiter {
    pub fn with_params(bucket: TokenBucket, established: TokenBucket, max_pending: usize) -> Self {
        Self {
            bucket,
            established,
            pending: Arc::new(AtomicUsize::new(0)),
            max_pending,
        }
    }

    #[cfg(test)]
    pub fn can_start_handshake(&mut self, class: Msg1Class) -> bool {
        self.bucket_for(class).available()
            && self.pending.load(Ordering::Relaxed) < self.max_pending
    }

    /// Consume a class token and acquire the shared pending slot.
    pub(in crate::node) fn start_handshake(
        &mut self,
        class: Msg1Class,
    ) -> Result<PendingHandshake, Msg1Refusal> {
        if self.pending.load(Ordering::Relaxed) >= self.max_pending {
            return Err(Msg1Refusal::PendingLimit);
        }
        if !self.bucket_for(class).try_acquire() {
            return Err(Msg1Refusal::RateLimit);
        }

        self.pending.fetch_add(1, Ordering::Relaxed);
        Ok(PendingHandshake {
            pending: Arc::clone(&self.pending),
        })
    }

    fn bucket_for(&mut self, class: Msg1Class) -> &mut TokenBucket {
        match class {
            Msg1Class::Stranger => &mut self.bucket,
            Msg1Class::EstablishedLink => &mut self.established,
        }
    }

    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn established_bucket(&self) -> &TokenBucket {
        &self.established
    }

    #[cfg(test)]
    pub fn reset(&mut self) {
        self.bucket.reset();
        self.established.reset();
        self.pending.store(0, Ordering::Relaxed);
    }
}

const SETUP_BUCKET_IDLE: Duration = Duration::from_secs(300);

struct SessionSetupBuckets {
    stranger: TokenBucket,
    established: TokenBucket,
    seen: Instant,
}

/// Per-authenticated-link-peer limiter for FSP SessionSetup messages.
///
/// The FSP source address is sender-chosen and must never be the key. Separate
/// stranger and established-session buckets prevent a half-open flood behind
/// one hop from suppressing legitimate peer-driven rekey traffic on that hop.
pub(in crate::node) struct SessionSetupRateLimiter {
    buckets: HashMap<NodeAddr, SessionSetupBuckets>,
    stranger: (u32, f64),
    established: (u32, f64),
}

impl SessionSetupRateLimiter {
    pub(in crate::node) fn with_params(stranger: (u32, f64), established: (u32, f64)) -> Self {
        Self {
            buckets: HashMap::new(),
            stranger,
            established,
        }
    }

    pub(in crate::node) fn try_admit(&mut self, link_peer: &NodeAddr, class: Msg1Class) -> bool {
        let now = instant_now();
        let stranger = self.stranger;
        let established = self.established;
        let buckets = self
            .buckets
            .entry(*link_peer)
            .or_insert_with(|| SessionSetupBuckets {
                stranger: TokenBucket::with_params(stranger.0, stranger.1),
                established: TokenBucket::with_params(established.0, established.1),
                seen: now,
            });
        buckets.seen = now;
        let admitted = match class {
            Msg1Class::Stranger => buckets.stranger.try_acquire(),
            Msg1Class::EstablishedLink => buckets.established.try_acquire(),
        };
        if admitted {
            self.buckets.retain(|_, candidate| {
                now.saturating_duration_since(candidate.seen) < SETUP_BUCKET_IDLE
            });
        }
        admitted
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::with_params(10, 1.0);

        // Should have full capacity
        assert_eq!(bucket.capacity(), 10);
        assert!(bucket.tokens() >= 9.9); // Allow for timing

        // Consume all tokens
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }

        // Should be empty
        assert!(!bucket.try_acquire());
        assert!(!bucket.available());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::with_params(10, 100.0); // 100 tokens/sec

        // Drain completely
        for _ in 0..10 {
            bucket.try_acquire();
        }
        assert!(!bucket.available());

        // Wait for refill, measuring actual elapsed time to avoid sensitivity
        // to OS scheduler variance (sleep can overshoot by a large margin).
        let before = Instant::now();
        thread::sleep(Duration::from_millis(50));
        let elapsed_secs = before.elapsed().as_secs_f64();

        // Expected tokens = elapsed * rate, capped at capacity.
        // Allow ±20% tolerance around the actual elapsed time.
        let expected = (elapsed_secs * 100.0).min(10.0);
        let lo = (expected * 0.8).min(expected - 0.5).max(0.0);
        let hi = (expected * 1.2).max(expected + 0.5).min(10.0);

        let tokens = bucket.tokens();
        assert!(
            (lo..=hi).contains(&tokens),
            "tokens: {}, expected ~{:.2} (range {:.2}..={:.2})",
            tokens,
            expected,
            lo,
            hi
        );
    }

    #[test]
    fn test_token_bucket_try_acquire_n() {
        let mut bucket = TokenBucket::with_params(10, 1.0);

        // Acquire 5
        assert!(bucket.try_acquire_n(5));
        assert!(bucket.tokens() >= 4.9 && bucket.tokens() <= 5.1);

        // Acquire 5 more
        assert!(bucket.try_acquire_n(5));

        // Can't acquire more
        assert!(!bucket.try_acquire_n(1));
    }

    #[test]
    fn test_token_bucket_reset() {
        let mut bucket = TokenBucket::with_params(10, 1.0);

        // Drain
        for _ in 0..10 {
            bucket.try_acquire();
        }

        // Reset
        bucket.reset();

        // Should be full again
        assert!(bucket.tokens() >= 9.9);
    }

    #[test]
    fn test_token_bucket_time_until_available() {
        let mut bucket = TokenBucket::with_params(10, 10.0); // 10 tokens/sec

        // When full, should be zero
        assert_eq!(bucket.time_until_available(), Duration::ZERO);

        // Drain completely
        for _ in 0..10 {
            bucket.try_acquire();
        }

        // Should need ~100ms for one token at 10/sec
        let wait = bucket.time_until_available();
        assert!(wait.as_millis() >= 90 && wait.as_millis() <= 110);
    }

    fn test_limiter(bucket: TokenBucket, max_pending: usize) -> HandshakeRateLimiter {
        HandshakeRateLimiter::with_params(
            bucket,
            TokenBucket::with_params(1000, 100.0),
            max_pending,
        )
    }

    #[test]
    fn test_handshake_rate_limiter_basic() {
        let mut limiter = test_limiter(TokenBucket::new(), 100);

        assert!(limiter.can_start_handshake(Msg1Class::Stranger));
        assert_eq!(limiter.pending_count(), 0);

        let slot = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        assert_eq!(limiter.pending_count(), 1);

        drop(slot);
        assert_eq!(limiter.pending_count(), 0);
    }

    #[test]
    fn test_handshake_rate_limiter_max_pending() {
        let mut limiter = test_limiter(TokenBucket::with_params(1000, 100.0), 3);

        let first = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        let _second = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        let _third = limiter.start_handshake(Msg1Class::Stranger).unwrap();

        assert!(!limiter.can_start_handshake(Msg1Class::Stranger));
        assert_eq!(
            limiter.start_handshake(Msg1Class::Stranger).unwrap_err(),
            Msg1Refusal::PendingLimit
        );

        drop(first);
        assert!(limiter.can_start_handshake(Msg1Class::Stranger));
        assert!(limiter.start_handshake(Msg1Class::Stranger).is_ok());
    }

    #[test]
    fn test_handshake_rate_limiter_token_exhaustion() {
        let mut limiter = test_limiter(TokenBucket::with_params(5, 0.0), 100);

        for _ in 0..5 {
            drop(limiter.start_handshake(Msg1Class::Stranger).unwrap());
        }

        assert_eq!(limiter.pending_count(), 0);
        assert!(!limiter.can_start_handshake(Msg1Class::Stranger));
        assert_eq!(
            limiter.start_handshake(Msg1Class::Stranger).unwrap_err(),
            Msg1Refusal::RateLimit
        );
    }

    #[test]
    fn pending_slot_releases_on_drop_and_saturates() {
        let mut limiter = test_limiter(TokenBucket::with_params(100, 100.0), 100);

        let outer = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        {
            let _inner = limiter.start_handshake(Msg1Class::Stranger).unwrap();
            assert_eq!(limiter.pending_count(), 2);
        }
        assert_eq!(limiter.pending_count(), 1);

        limiter.reset();
        drop(outer);
        assert_eq!(limiter.pending_count(), 0, "guard drop must not underflow");
    }

    #[test]
    fn msg1_classes_draw_on_separate_buckets() {
        let mut limiter = HandshakeRateLimiter::with_params(
            TokenBucket::with_params(1, 0.0),
            TokenBucket::with_params(3, 0.0),
            100,
        );

        drop(limiter.start_handshake(Msg1Class::Stranger).unwrap());
        assert_eq!(
            limiter.start_handshake(Msg1Class::Stranger).unwrap_err(),
            Msg1Refusal::RateLimit
        );

        for _ in 0..3 {
            drop(
                limiter
                    .start_handshake(Msg1Class::EstablishedLink)
                    .expect("established-link capacity must be independent"),
            );
        }
        assert_eq!(
            limiter
                .start_handshake(Msg1Class::EstablishedLink)
                .unwrap_err(),
            Msg1Refusal::RateLimit
        );
    }

    #[test]
    fn derive_established_bucket_from_defaults_and_unlimited_peers() {
        let (burst, rate) = derive_established_bucket(128, 120, 5, 100, 10.0);
        assert_eq!(burst, 128);
        assert!((rate - 6.4).abs() < 1e-9);

        let (burst, rate) = derive_established_bucket(512, 120, 5, 100, 10.0);
        assert_eq!(burst, 512);
        assert!((rate - 25.6).abs() < 1e-9);

        assert_eq!(derive_established_bucket(0, 120, 5, 100, 10.0), (100, 10.0));
    }

    #[test]
    fn derive_established_bucket_handles_degenerate_rekey_periods() {
        let (_, zero_period_rate) = derive_established_bucket(128, 0, 5, 100, 10.0);
        assert_eq!(
            zero_period_rate,
            derive_established_bucket(128, 1, 5, 100, 10.0).1
        );
        assert!(zero_period_rate.is_finite());

        let (_, long_period_rate) = derive_established_bucket(1, 100_000, 5, 100, 10.0);
        assert_eq!(long_period_rate, ESTABLISHED_RATE_FLOOR);
    }

    #[test]
    fn setup_limiter_is_per_peer_and_keeps_established_budget_separate() {
        let mut limiter = SessionSetupRateLimiter::with_params((1, 0.001), (1, 0.001));
        let noisy = NodeAddr::from_bytes([1; 16]);
        let quiet = NodeAddr::from_bytes([2; 16]);
        assert!(limiter.try_admit(&noisy, Msg1Class::Stranger));
        assert!(!limiter.try_admit(&noisy, Msg1Class::Stranger));
        assert!(limiter.try_admit(&quiet, Msg1Class::Stranger));
        assert!(limiter.try_admit(&noisy, Msg1Class::EstablishedLink));
        assert_eq!(limiter.len(), 2);
    }
}
