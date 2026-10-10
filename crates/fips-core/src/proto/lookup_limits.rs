//! Discovery protocol rate limiting and backoff.
//!
//! Two complementary mechanisms:
//!
//! - **`DiscoveryBackoff`** (originator-side, optional): Exponential
//!   suppression of fresh lookups after the per-attempt sequence in
//!   `node.discovery.attempt_timeouts_secs` has been exhausted. Reset on
//!   topology changes (parent change, new peer, first RTT, reconnection).
//!   A lookup whose first request was delayed by missing reachability may retry
//!   once when local demand finds a usable route, without clearing failure history.
//!
//! - **`DiscoveryForwardRateLimiter`** (transit-side): Per-ingress/origin/target minimum
//!   interval plus a per-authenticated-ingress budget for forwarded requests.
//!   Defense-in-depth against misbehaving nodes generating fresh request_ids
//!   and targets at high rate.

use crate::NodeAddr;
use crate::time::{Instant, instant_now};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

// ============================================================================
// Originator-side: Discovery Backoff
// ============================================================================

/// Default base backoff after first lookup failure. `0` = disabled.
const DEFAULT_BACKOFF_BASE_SECS: u64 = 30;

/// Default maximum backoff cap. `0` = disabled.
const DEFAULT_BACKOFF_MAX_SECS: u64 = 300;

/// Backoff multiplier per consecutive failure.
const BACKOFF_MULTIPLIER: u64 = 2;

/// Exponential backoff for failed discovery lookups.
///
/// Tracks targets whose lookups have timed out and suppresses
/// re-initiation with increasing delays. Cleared on topology changes.
pub struct DiscoveryBackoff {
    /// Maps target → (suppress_until, consecutive_failures).
    entries: HashMap<NodeAddr, BackoffEntry>,
    /// Base backoff duration (first failure).
    base: Duration,
    /// Maximum backoff cap.
    max: Duration,
}

struct BackoffEntry {
    /// Don't re-initiate until this instant.
    suppress_until: Instant,
    /// Consecutive failures (drives exponential backoff).
    failures: u32,
    /// Missing reachability delayed the failed lookup's first request.
    retry_when_reachable: bool,
}

impl DiscoveryBackoff {
    /// Create with default parameters.
    pub fn new() -> Self {
        Self::with_params(DEFAULT_BACKOFF_BASE_SECS, DEFAULT_BACKOFF_MAX_SECS)
    }

    /// Create with custom base and max backoff in seconds.
    pub fn with_params(base_secs: u64, max_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            base: Duration::from_secs(base_secs),
            max: Duration::from_secs(max_secs),
        }
    }

    /// Check if a lookup for this target is suppressed.
    ///
    /// Returns true if the target is in backoff and should not be
    /// looked up yet.
    pub fn is_suppressed(&self, target: &NodeAddr) -> bool {
        if let Some(entry) = self.entries.get(target) {
            instant_now() < entry.suppress_until
        } else {
            false
        }
    }

    /// Record a lookup failure (timeout) for a target.
    ///
    /// Increments the failure count and sets the next suppression
    /// window using exponential backoff.
    pub fn record_failure(&mut self, target: &NodeAddr) {
        self.record_failure_with_reachability(target, false);
    }

    /// Record failure when no peer was selected during the initial attempt.
    pub(crate) fn record_delayed_failure(&mut self, target: &NodeAddr) {
        self.record_failure_with_reachability(target, true);
    }

    fn record_failure_with_reachability(&mut self, target: &NodeAddr, retry_when_reachable: bool) {
        let now = instant_now();
        let failures = self.entries.get(target).map_or(0, |e| e.failures) + 1;

        let backoff_secs = self
            .base
            .as_secs()
            .saturating_mul(BACKOFF_MULTIPLIER.saturating_pow(failures.saturating_sub(1)));
        let backoff = Duration::from_secs(backoff_secs.min(self.max.as_secs()));

        self.entries.insert(
            *target,
            BackoffEntry {
                suppress_until: now + backoff,
                failures,
                retry_when_reachable,
            },
        );
    }

    /// Spend one retry on newly usable reachability. The caller must apply
    /// normal lookup admission and peer selection first. A routing hint does
    /// not prove delivery, so the failure count and suppression deadline stay.
    pub(crate) fn retry_delayed_with_route(&mut self, target: &NodeAddr) -> bool {
        self.entries
            .get_mut(target)
            .is_some_and(|entry| std::mem::take(&mut entry.retry_when_reachable))
    }

    /// Record a successful lookup — remove backoff for this target.
    pub fn record_success(&mut self, target: &NodeAddr) {
        self.entries.remove(target);
    }

    /// Clear all backoff entries.
    ///
    /// Called on topology changes that might make previously-unreachable
    /// targets reachable (parent change, new peer, first RTT, reconnection).
    pub fn reset_all(&mut self) {
        self.entries.clear();
    }

    /// Whether any entries exist.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the failure count for a target (for logging).
    pub fn failure_count(&self, target: &NodeAddr) -> u32 {
        self.entries.get(target).map_or(0, |e| e.failures)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for DiscoveryBackoff {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Transit-side: Discovery Forward Rate Limiter
// ============================================================================

/// Default minimum interval between lookups for the same origin and target.
const DEFAULT_FORWARD_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum age of entries before cleanup.
const FORWARD_MAX_AGE: Duration = Duration::from_secs(60);

/// Sweep stale limiter state at most this often. A time gate keeps admission
/// bounded between sweeps instead of walking the target map after every forward.
const FORWARD_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

/// Hard bounds for attacker-controlled forwarding state.
const FORWARD_MAX_TARGETS: usize = 4_096;
const FORWARD_MAX_INGRESS_PEERS: usize = 4_096;

/// A transit peer may legitimately aggregate lookups for a subtree, so keep a
/// generous burst while bounding sustained target churn from that peer.
const DEFAULT_FORWARD_BURST: f64 = 256.0;
const DEFAULT_FORWARD_RATE: f64 = 32.0;
const FORWARD_INGRESS_MAX_AGE: Duration = Duration::from_secs(300);

struct DiscoveryForwardBucket {
    tokens: f64,
    updated: Instant,
}

#[cfg(test)]
struct DiscoveryForwardTestParams {
    min_interval: Duration,
    max_age: Duration,
    max_targets: usize,
    max_ingress_peers: usize,
    ingress_burst: f64,
    ingress_rate: f64,
    ingress_max_age: Duration,
    cleanup_interval: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscoveryForwardDecision {
    Forward,
    TargetInterval,
    TargetCapacity,
    IngressCapacity,
    IngressBudget,
}

/// Rate limiter for forwarded discovery requests.
///
/// Tracks the last forward for each authenticated ingress, claimed origin and target.
/// Enforces a minimum interval to prevent floods from misbehaving nodes
/// generating fresh request_ids. Both target state and per-ingress token
/// buckets are hard-capped. Cleanup is time-amortized rather than performed on
/// every admitted request.
pub struct DiscoveryForwardRateLimiter {
    last_forwarded: HashMap<(NodeAddr, NodeAddr, NodeAddr), Instant>,
    /// One entry per scope; find reusable cooldowns without scanning a full map.
    forwarded_by_time: BTreeSet<(Instant, (NodeAddr, NodeAddr, NodeAddr))>,
    ingress_buckets: HashMap<NodeAddr, DiscoveryForwardBucket>,
    min_interval: Duration,
    max_age: Duration,
    max_targets: usize,
    max_ingress_peers: usize,
    ingress_burst: f64,
    ingress_rate: f64,
    ingress_max_age: Duration,
    cleanup_interval: Duration,
    last_cleanup: Instant,
}

impl DiscoveryForwardRateLimiter {
    /// Create with default parameters (2s interval).
    pub fn new() -> Self {
        Self::with_interval(DEFAULT_FORWARD_MIN_INTERVAL)
    }

    /// Create with a custom minimum interval.
    pub fn with_interval(min_interval: Duration) -> Self {
        let now = instant_now();
        Self {
            last_forwarded: HashMap::new(),
            forwarded_by_time: BTreeSet::new(),
            ingress_buckets: HashMap::new(),
            min_interval,
            max_age: FORWARD_MAX_AGE,
            max_targets: FORWARD_MAX_TARGETS,
            max_ingress_peers: FORWARD_MAX_INGRESS_PEERS,
            ingress_burst: DEFAULT_FORWARD_BURST,
            ingress_rate: DEFAULT_FORWARD_RATE,
            ingress_max_age: FORWARD_INGRESS_MAX_AGE,
            cleanup_interval: FORWARD_CLEANUP_INTERVAL,
            last_cleanup: now,
        }
    }

    /// Check if we should forward a lookup from this authenticated ingress
    /// peer for this target.
    ///
    /// Returns true if enough time has passed since the last forward for this
    /// originating peer and target, and the ingress peer has forwarding budget.
    /// Updates state only on success, apart from the bounded ingress bucket.
    #[cfg(test)]
    pub fn should_forward(&mut self, from: &NodeAddr, target: &NodeAddr) -> bool {
        self.should_forward_for_origin(from, from, target)
    }

    /// Admit an independent origin sharing this authenticated ingress.
    /// `origin` is an untrusted claim, used only for duplicate suppression.
    /// Changing it cannot bypass the ingress budget or the retained-state cap,
    /// or reserve another authenticated ingress's retry slot.
    pub fn should_forward_for_origin(
        &mut self,
        from: &NodeAddr,
        origin: &NodeAddr,
        target: &NodeAddr,
    ) -> bool {
        let now = instant_now();
        self.decision_for_origin_at(from, origin, target, now) == DiscoveryForwardDecision::Forward
    }

    #[cfg(test)]
    fn decision_at(
        &mut self,
        from: &NodeAddr,
        target: &NodeAddr,
        now: Instant,
    ) -> DiscoveryForwardDecision {
        self.decision_for_origin_at(from, from, target, now)
    }

    fn decision_for_origin_at(
        &mut self,
        from: &NodeAddr,
        origin: &NodeAddr,
        target: &NodeAddr,
        now: Instant,
    ) -> DiscoveryForwardDecision {
        self.maybe_cleanup(now);
        let key = (*from, *origin, *target);

        if let Some(&last) = self.last_forwarded.get(&key)
            && now.saturating_duration_since(last) < self.min_interval
        {
            return DiscoveryForwardDecision::TargetInterval;
        }

        let reclaim = if !self.last_forwarded.contains_key(&key)
            && self.last_forwarded.len() >= self.max_targets
        {
            let Some(&(last, oldest)) = self.forwarded_by_time.first() else {
                return DiscoveryForwardDecision::TargetCapacity;
            };
            if now.saturating_duration_since(last) < self.min_interval {
                return DiscoveryForwardDecision::TargetCapacity;
            }
            Some((last, oldest))
        } else {
            None
        };

        let ingress_rate = self.ingress_rate;
        let ingress_burst = self.ingress_burst;
        let Some(bucket) = self.ingress_bucket(from, now) else {
            return DiscoveryForwardDecision::IngressCapacity;
        };
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * ingress_rate).min(ingress_burst);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            return DiscoveryForwardDecision::IngressBudget;
        }
        bucket.tokens -= 1.0;

        // A cooldown may be reused before idle cleanup, but a rejected ingress
        // must not evict even expired state. Preserve live per-scope intervals.
        if let Some((last, oldest)) = reclaim {
            self.last_forwarded.remove(&oldest);
            self.forwarded_by_time.remove(&(last, oldest));
        }
        if let Some(last) = self.last_forwarded.insert(key, now) {
            self.forwarded_by_time.remove(&(last, key));
        }
        self.forwarded_by_time.insert((now, key));
        DiscoveryForwardDecision::Forward
    }

    /// An authenticated ingress may wait for the next target slot, including
    /// one aggregating requests from several origins behind the same peer.
    /// Admission checks the ingress budget, but only dispatch consumes it.
    pub(crate) fn deferred_deadline(
        &mut self,
        from: &NodeAddr,
        origin: &NodeAddr,
        target: &NodeAddr,
    ) -> Option<Instant> {
        let now = instant_now();
        let last = if let Some(&last) = self.last_forwarded.get(&(*from, *origin, *target)) {
            last
        } else if self.last_forwarded.len() >= self.max_targets {
            self.forwarded_by_time.first()?.0
        } else {
            return None;
        };
        let due = last.checked_add(self.min_interval)?;
        if now >= due {
            return None;
        }
        let rate = self.ingress_rate;
        let burst = self.ingress_burst;
        let bucket = self.ingress_bucket(from, now)?;
        let available = (bucket.tokens
            + now.saturating_duration_since(bucket.updated).as_secs_f64() * rate)
            .min(burst);
        (available >= 1.0).then_some(due)
    }

    fn ingress_bucket(
        &mut self,
        from: &NodeAddr,
        now: Instant,
    ) -> Option<&mut DiscoveryForwardBucket> {
        if !self.ingress_buckets.contains_key(from) {
            if self.ingress_buckets.len() >= self.max_ingress_peers {
                return None;
            }
            self.ingress_buckets.insert(
                *from,
                DiscoveryForwardBucket {
                    tokens: self.ingress_burst,
                    updated: now,
                },
            );
        }
        self.ingress_buckets.get_mut(from)
    }

    /// Replace the minimum interval (e.g., set to zero to disable).
    #[cfg(test)]
    pub fn set_interval(&mut self, interval: Duration) {
        self.min_interval = interval;
    }

    fn maybe_cleanup(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_cleanup) < self.cleanup_interval {
            return;
        }
        self.cleanup(now);
    }

    /// Remove stale entries. This full-map work is only reached through the
    /// time-amortized gate above in production.
    fn cleanup(&mut self, now: Instant) {
        self.last_forwarded.retain(|key, last| {
            let keep = now.saturating_duration_since(*last) < self.max_age;
            if !keep {
                self.forwarded_by_time.remove(&(*last, *key));
            }
            keep
        });
        self.ingress_buckets.retain(|_, bucket| {
            now.saturating_duration_since(bucket.updated) < self.ingress_max_age
        });
        self.last_cleanup = now;
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.last_forwarded.len()
    }

    #[cfg(test)]
    fn ingress_len(&self) -> usize {
        self.ingress_buckets.len()
    }

    #[cfg(test)]
    fn with_test_params(now: Instant, params: DiscoveryForwardTestParams) -> Self {
        Self {
            last_forwarded: HashMap::new(),
            forwarded_by_time: BTreeSet::new(),
            ingress_buckets: HashMap::new(),
            min_interval: params.min_interval,
            max_age: params.max_age,
            max_targets: params.max_targets,
            max_ingress_peers: params.max_ingress_peers,
            ingress_burst: params.ingress_burst,
            ingress_rate: params.ingress_rate,
            ingress_max_age: params.ingress_max_age,
            cleanup_interval: params.cleanup_interval,
            last_cleanup: now,
        }
    }
}

impl Default for DiscoveryForwardRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Target-side: Lookup response signing budget
// ============================================================================

const DEFAULT_SIGN_BURST: f64 = 256.0;
const DEFAULT_SIGN_RATE: f64 = 32.0;
const SIGN_MAX_AGE: Duration = Duration::from_secs(300);

struct LookupSignBucket {
    tokens: f64,
    updated: Instant,
}

/// Per-authenticated-ingress-peer budget for answering lookups about this
/// node. Each request ID requires a fresh Schnorr signature.
pub struct LookupSignRateLimiter {
    buckets: HashMap<NodeAddr, LookupSignBucket>,
    burst: f64,
    rate: f64,
}

impl LookupSignRateLimiter {
    pub fn new() -> Self {
        Self::with_params(DEFAULT_SIGN_BURST, DEFAULT_SIGN_RATE)
    }

    pub fn with_params(burst: f64, rate: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            burst,
            rate,
        }
    }

    /// Spend one signing token. A zero burst deliberately means unlimited,
    /// preventing configuration from making the node wholly unresolvable.
    pub fn should_sign(&mut self, from: &NodeAddr) -> bool {
        if self.burst <= 0.0 {
            return true;
        }
        let now = instant_now();
        let bucket = self.buckets.entry(*from).or_insert(LookupSignBucket {
            tokens: self.burst,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        self.buckets
            .retain(|_, candidate| now.saturating_duration_since(candidate.updated) < SIGN_MAX_AGE);
        true
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }
}

impl Default for LookupSignRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn numbered_addr(val: u32) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&val.to_le_bytes());
        NodeAddr::from_bytes(bytes)
    }

    // --- DiscoveryBackoff tests ---

    #[test]
    fn test_backoff_not_suppressed_initially() {
        let backoff = DiscoveryBackoff::new();
        assert!(!backoff.is_suppressed(&addr(1)));
    }

    #[test]
    fn test_backoff_suppressed_after_failure() {
        // Backoff is opt-in; exercise the suppression path with explicit params.
        let mut backoff = DiscoveryBackoff::with_params(30, 300);
        backoff.record_failure(&addr(1));
        assert!(backoff.is_suppressed(&addr(1)));
        // Different target not affected
        assert!(!backoff.is_suppressed(&addr(2)));
    }

    #[test]
    fn test_backoff_cleared_on_success() {
        let mut backoff = DiscoveryBackoff::with_params(30, 300);
        backoff.record_failure(&addr(1));
        assert!(backoff.is_suppressed(&addr(1)));

        backoff.record_success(&addr(1));
        assert!(!backoff.is_suppressed(&addr(1)));
    }

    #[test]
    fn test_backoff_reset_all() {
        let mut backoff = DiscoveryBackoff::new();
        backoff.record_failure(&addr(1));
        backoff.record_failure(&addr(2));
        assert_eq!(backoff.len(), 2);

        backoff.reset_all();
        assert_eq!(backoff.len(), 0);
        assert!(!backoff.is_suppressed(&addr(1)));
    }

    #[test]
    fn test_backoff_exponential() {
        let mut backoff = DiscoveryBackoff::with_params(1, 300);

        // First failure: 1s backoff
        backoff.record_failure(&addr(1));
        assert_eq!(backoff.failure_count(&addr(1)), 1);

        // Second failure: 2s backoff
        backoff.record_failure(&addr(1));
        assert_eq!(backoff.failure_count(&addr(1)), 2);

        // Third failure: 4s backoff
        backoff.record_failure(&addr(1));
        assert_eq!(backoff.failure_count(&addr(1)), 3);
    }

    #[test]
    fn test_backoff_expires() {
        let mut backoff = DiscoveryBackoff::with_params(0, 0);
        backoff.record_failure(&addr(1));
        // With 0s backoff, should not be suppressed
        assert!(!backoff.is_suppressed(&addr(1)));
    }

    #[test]
    fn test_backoff_capped() {
        let mut backoff = DiscoveryBackoff::with_params(1, 10);

        // Record many failures
        for _ in 0..20 {
            backoff.record_failure(&addr(1));
        }

        // Backoff should be capped at max (10s), not overflow
        let entry = backoff.entries.get(&addr(1)).unwrap();
        let remaining = entry.suppress_until.duration_since(Instant::now());
        assert!(remaining <= Duration::from_secs(11));
    }

    #[test]
    fn delayed_failure_allows_one_targeted_retry_without_erasing_history() {
        let mut backoff = DiscoveryBackoff::new();
        backoff.record_delayed_failure(&addr(1));
        backoff.record_delayed_failure(&addr(2));
        let deadline = backoff.entries[&addr(1)].suppress_until;

        assert!(backoff.retry_delayed_with_route(&addr(1)));
        assert!(!backoff.retry_delayed_with_route(&addr(1)));
        assert!(backoff.is_suppressed(&addr(1)));
        assert_eq!(backoff.failure_count(&addr(1)), 1);
        assert_eq!(backoff.entries[&addr(1)].suppress_until, deadline);
        assert!(backoff.is_suppressed(&addr(2)));
        assert!(backoff.entries[&addr(2)].retry_when_reachable);
        assert_eq!(backoff.entry_count(), 2);
    }

    #[test]
    fn unanswered_retry_restores_increasing_backoff_despite_repeated_hints() {
        let mut backoff = DiscoveryBackoff::new();
        backoff.record_delayed_failure(&addr(1));
        let first_deadline = backoff.entries[&addr(1)].suppress_until;
        assert!(backoff.retry_delayed_with_route(&addr(1)));
        backoff.record_failure(&addr(1));

        assert_eq!(backoff.failure_count(&addr(1)), 2);
        assert!(backoff.entries[&addr(1)].suppress_until >= first_deadline + backoff.base);
        for _ in 0..100 {
            assert!(!backoff.retry_delayed_with_route(&addr(1)));
            assert!(backoff.is_suppressed(&addr(1)));
        }
    }

    #[test]
    fn ordinary_and_unknown_targets_never_gain_a_delayed_retry() {
        let mut backoff = DiscoveryBackoff::new();
        backoff.record_failure(&addr(1));
        assert!(!backoff.retry_delayed_with_route(&addr(1)));
        assert!(!backoff.retry_delayed_with_route(&addr(2)));
        assert_eq!(backoff.entry_count(), 1);

        backoff.record_delayed_failure(&addr(2));
        backoff.record_success(&addr(2));
        assert!(!backoff.retry_delayed_with_route(&addr(2)));
        backoff.record_delayed_failure(&addr(2));
        backoff.reset_all();
        assert!(!backoff.retry_delayed_with_route(&addr(2)));
        assert!(backoff.is_empty());
    }

    mod capacity;
    mod deferred;
    mod origins;

    // --- DiscoveryForwardRateLimiter tests ---

    #[test]
    fn test_forward_first_allowed() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(99), &addr(1)));
    }

    #[test]
    fn distinct_ingresses_can_discover_one_target_concurrently() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        for ingress in 1..=16 {
            assert!(limiter.should_forward(&addr(ingress), &addr(99)));
        }
    }

    #[test]
    fn test_forward_rapid_rate_limited() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(99), &addr(1)));
        assert!(!limiter.should_forward(&addr(99), &addr(1)));
        assert!(!limiter.should_forward(&addr(99), &addr(1)));
    }

    #[test]
    fn test_forward_different_targets_independent() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(99), &addr(1)));
        assert!(limiter.should_forward(&addr(99), &addr(2)));
        assert!(!limiter.should_forward(&addr(99), &addr(1)));
        assert!(!limiter.should_forward(&addr(99), &addr(2)));
    }

    #[test]
    fn lookup_sign_budget_is_independent_per_ingress_peer() {
        let mut limiter = LookupSignRateLimiter::with_params(4.0, 0.0);
        for _ in 0..4 {
            assert!(limiter.should_sign(&addr(1)));
        }
        assert!(!limiter.should_sign(&addr(1)));
        assert!(limiter.should_sign(&addr(2)));
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn zero_lookup_sign_burst_means_unlimited_without_state() {
        let mut limiter = LookupSignRateLimiter::with_params(0.0, 0.0);
        for _ in 0..1_000 {
            assert!(limiter.should_sign(&addr(1)));
        }
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn test_forward_allowed_at_interval_boundary() {
        let interval = Duration::from_millis(100);
        let mut limiter = DiscoveryForwardRateLimiter::with_interval(interval);
        let now = instant_now();
        for (elapsed, expected) in [
            (Duration::ZERO, DiscoveryForwardDecision::Forward),
            (
                interval - Duration::from_nanos(1),
                DiscoveryForwardDecision::TargetInterval,
            ),
            (interval, DiscoveryForwardDecision::Forward),
        ] {
            assert_eq!(
                limiter.decision_at(&addr(99), &addr(1), now + elapsed),
                expected
            );
        }
    }

    #[test]
    fn test_forward_cleanup_removes_old() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(99), &addr(1)));
        assert!(limiter.should_forward(&addr(99), &addr(2)));
        assert_eq!(limiter.len(), 2);

        let future = Instant::now() + Duration::from_secs(61);
        limiter.cleanup(future);
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn test_forward_cleanup_preserves_recent() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        assert!(limiter.should_forward(&addr(99), &addr(1)));
        assert_eq!(limiter.len(), 1);

        limiter.cleanup(Instant::now());
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn forward_unique_target_flood_is_hard_capped() {
        let now = Instant::now();
        let mut limiter = DiscoveryForwardRateLimiter::with_test_params(
            now,
            DiscoveryForwardTestParams {
                min_interval: DEFAULT_FORWARD_MIN_INTERVAL,
                max_age: Duration::from_secs(60),
                max_targets: 8,
                max_ingress_peers: 8,
                ingress_burst: 32.0,
                ingress_rate: 0.0,
                ingress_max_age: Duration::from_secs(300),
                cleanup_interval: Duration::from_secs(5),
            },
        );
        let ingress = numbered_addr(10_000);

        for target in 0..8 {
            assert_eq!(
                limiter.decision_at(&ingress, &numbered_addr(target), now),
                DiscoveryForwardDecision::Forward
            );
        }
        assert_eq!(
            limiter.decision_at(&ingress, &numbered_addr(9), now),
            DiscoveryForwardDecision::TargetCapacity
        );
        assert_eq!(limiter.len(), 8);
    }

    #[test]
    fn shipped_forwarding_limits_bound_a_multi_peer_target_flood() {
        let mut limiter = DiscoveryForwardRateLimiter::new();
        let now = Instant::now();
        let burst = DEFAULT_FORWARD_BURST as u32;

        for target in 0..FORWARD_MAX_TARGETS as u32 {
            let ingress = numbered_addr(10_000 + target / burst);
            assert_eq!(
                limiter.decision_at(&ingress, &numbered_addr(target), now),
                DiscoveryForwardDecision::Forward
            );
        }
        assert_eq!(
            limiter.decision_at(
                &numbered_addr(10_000 + FORWARD_MAX_TARGETS as u32 / burst),
                &numbered_addr(FORWARD_MAX_TARGETS as u32),
                now,
            ),
            DiscoveryForwardDecision::TargetCapacity
        );
        assert_eq!(limiter.len(), FORWARD_MAX_TARGETS);
    }

    #[test]
    fn forwarding_budget_rejects_before_allocating_unique_target_state() {
        let now = Instant::now();
        let mut limiter = DiscoveryForwardRateLimiter::with_test_params(
            now,
            DiscoveryForwardTestParams {
                min_interval: Duration::ZERO,
                max_age: Duration::from_secs(60),
                max_targets: 32,
                max_ingress_peers: 8,
                ingress_burst: 2.0,
                ingress_rate: 0.0,
                ingress_max_age: Duration::from_secs(300),
                cleanup_interval: Duration::from_secs(5),
            },
        );
        let noisy_ingress = numbered_addr(10_000);
        let quiet_ingress = numbered_addr(10_001);

        assert_eq!(
            limiter.decision_at(&noisy_ingress, &numbered_addr(1), now),
            DiscoveryForwardDecision::Forward
        );
        assert_eq!(
            limiter.decision_at(&noisy_ingress, &numbered_addr(2), now),
            DiscoveryForwardDecision::Forward
        );
        assert_eq!(
            limiter.decision_at(&noisy_ingress, &numbered_addr(3), now),
            DiscoveryForwardDecision::IngressBudget
        );
        assert_eq!(limiter.len(), 2, "rejected target must not allocate state");

        assert_eq!(
            limiter.decision_at(&quiet_ingress, &numbered_addr(3), now),
            DiscoveryForwardDecision::Forward,
            "one noisy authenticated peer must not consume another peer's budget"
        );
        assert_eq!(limiter.len(), 3);
        assert_eq!(limiter.ingress_len(), 2);
    }

    #[test]
    fn forwarding_budget_refills_for_sustained_legitimate_lookups() {
        let now = Instant::now();
        let mut limiter = DiscoveryForwardRateLimiter::with_test_params(
            now,
            DiscoveryForwardTestParams {
                min_interval: Duration::ZERO,
                max_age: Duration::from_secs(60),
                max_targets: 32,
                max_ingress_peers: 8,
                ingress_burst: 1.0,
                ingress_rate: 2.0,
                ingress_max_age: Duration::from_secs(300),
                cleanup_interval: Duration::from_secs(5),
            },
        );
        let ingress = numbered_addr(10_000);

        assert_eq!(
            limiter.decision_at(&ingress, &numbered_addr(1), now),
            DiscoveryForwardDecision::Forward
        );
        assert_eq!(
            limiter.decision_at(&ingress, &numbered_addr(2), now),
            DiscoveryForwardDecision::IngressBudget
        );
        assert_eq!(
            limiter.decision_at(
                &ingress,
                &numbered_addr(2),
                now + Duration::from_millis(500),
            ),
            DiscoveryForwardDecision::Forward
        );
    }

    #[test]
    fn forwarding_cleanup_is_time_amortized() {
        let now = Instant::now();
        let cleanup_interval = Duration::from_secs(5);
        let mut limiter = DiscoveryForwardRateLimiter::with_test_params(
            now,
            DiscoveryForwardTestParams {
                min_interval: Duration::ZERO,
                max_age: Duration::ZERO,
                max_targets: 32,
                max_ingress_peers: 8,
                ingress_burst: 32.0,
                ingress_rate: 0.0,
                ingress_max_age: Duration::ZERO,
                cleanup_interval,
            },
        );
        let ingress = numbered_addr(10_000);

        for target in 0..16 {
            assert_eq!(
                limiter.decision_at(&ingress, &numbered_addr(target), now),
                DiscoveryForwardDecision::Forward
            );
        }
        assert_eq!(
            limiter.len(),
            16,
            "admission must not sweep the whole map on every insert"
        );

        assert_eq!(
            limiter.decision_at(&ingress, &numbered_addr(100), now + cleanup_interval),
            DiscoveryForwardDecision::Forward
        );
        assert_eq!(
            limiter.len(),
            1,
            "the scheduled sweep removes stale targets"
        );
        assert_eq!(limiter.ingress_len(), 1);
    }

    #[test]
    fn forwarding_ingress_state_is_hard_capped() {
        let now = Instant::now();
        let mut limiter = DiscoveryForwardRateLimiter::with_test_params(
            now,
            DiscoveryForwardTestParams {
                min_interval: Duration::ZERO,
                max_age: Duration::from_secs(60),
                max_targets: 32,
                max_ingress_peers: 2,
                ingress_burst: 4.0,
                ingress_rate: 0.0,
                ingress_max_age: Duration::from_secs(300),
                cleanup_interval: Duration::from_secs(5),
            },
        );

        assert_eq!(
            limiter.decision_at(&numbered_addr(10), &numbered_addr(1), now),
            DiscoveryForwardDecision::Forward
        );
        assert_eq!(
            limiter.decision_at(&numbered_addr(11), &numbered_addr(2), now),
            DiscoveryForwardDecision::Forward
        );
        assert_eq!(
            limiter.decision_at(&numbered_addr(12), &numbered_addr(3), now),
            DiscoveryForwardDecision::IngressCapacity
        );
        assert_eq!(limiter.ingress_len(), 2);
        assert_eq!(limiter.len(), 2);
    }
}
