//! Per-authenticated-link-peer budget for induced routing-error emissions.
//!
//! Datagram source and destination fields are sender-controlled. The peer
//! that authenticated the enclosing FMP frame is the only stable key at the
//! emission point, so this bucket is the flood/reflection bound.

use crate::NodeAddr;
use crate::time::Instant;
use std::collections::HashMap;
use std::time::Duration;

pub(in crate::node) const PEER_ERROR_RATE_PER_SEC: u32 = 20;
pub(in crate::node) const PEER_ERROR_BURST: u32 = 50;

const MILLI: u64 = 1_000;
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct Bucket {
    milli_tokens: u64,
    last_refill: Instant,
}

pub(in crate::node) struct PeerErrorBudget {
    buckets: HashMap<NodeAddr, Bucket>,
    milli_per_ms: u64,
    capacity: u64,
    last_sweep: Instant,
}

impl PeerErrorBudget {
    pub(in crate::node) fn new() -> Self {
        Self::with_rate(PEER_ERROR_RATE_PER_SEC, PEER_ERROR_BURST)
    }

    fn with_rate(per_sec: u32, burst: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            milli_per_ms: u64::from(per_sec),
            capacity: u64::from(burst) * MILLI,
            last_sweep: crate::time::instant_now(),
        }
    }

    /// Peek without spending, so suppression by a later destination gate does
    /// not consume the peer's budget.
    pub(in crate::node) fn has_token(&mut self, peer: &NodeAddr, now: Instant) -> bool {
        self.refill(peer, now);
        self.buckets
            .get(peer)
            .is_some_and(|bucket| bucket.milli_tokens >= MILLI)
    }

    pub(in crate::node) fn commit(&mut self, peer: &NodeAddr, now: Instant) {
        self.refill(peer, now);
        if let Some(bucket) = self.buckets.get_mut(peer) {
            bucket.milli_tokens = bucket.milli_tokens.saturating_sub(MILLI);
        }
        self.sweep(now);
    }

    fn refill(&mut self, peer: &NodeAddr, now: Instant) {
        let capacity = self.capacity;
        let milli_per_ms = self.milli_per_ms;
        let bucket = self.buckets.entry(*peer).or_insert(Bucket {
            milli_tokens: capacity,
            last_refill: now,
        });
        let elapsed_ms = now
            .saturating_duration_since(bucket.last_refill)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        if elapsed_ms > 0 {
            bucket.milli_tokens = bucket
                .milli_tokens
                .saturating_add(elapsed_ms.saturating_mul(milli_per_ms))
                .min(capacity);
            bucket.last_refill = now;
        }
    }

    fn sweep(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        let capacity = self.capacity;
        let milli_per_ms = self.milli_per_ms;
        self.buckets.retain(|_, bucket| {
            let elapsed_ms = now
                .saturating_duration_since(bucket.last_refill)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
            bucket
                .milli_tokens
                .saturating_add(elapsed_ms.saturating_mul(milli_per_ms))
                < capacity
        });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

impl Default for PeerErrorBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(value: u8) -> NodeAddr {
        let mut bytes = [0; 16];
        bytes[0] = value;
        NodeAddr::from_bytes(bytes)
    }

    fn spend(budget: &mut PeerErrorBudget, peer: &NodeAddr, now: Instant) -> bool {
        if !budget.has_token(peer, now) {
            return false;
        }
        budget.commit(peer, now);
        true
    }

    #[test]
    fn burst_then_sustained_rate_is_enforced_per_peer() {
        let mut budget = PeerErrorBudget::new();
        let start = crate::time::instant_now();
        let peer = addr(1);
        for _ in 0..PEER_ERROR_BURST {
            assert!(spend(&mut budget, &peer, start));
        }
        assert!(!spend(&mut budget, &peer, start));

        let later = start + Duration::from_secs(1);
        for _ in 0..PEER_ERROR_RATE_PER_SEC {
            assert!(spend(&mut budget, &peer, later));
        }
        assert!(!spend(&mut budget, &peer, later));
    }

    #[test]
    fn peers_have_independent_budgets_and_peeks_do_not_spend() {
        let mut budget = PeerErrorBudget::with_rate(1, 1);
        let now = crate::time::instant_now();
        let first = addr(1);
        let second = addr(2);
        assert!(budget.has_token(&first, now));
        assert!(budget.has_token(&first, now));
        budget.commit(&first, now);
        assert!(!budget.has_token(&first, now));
        assert!(budget.has_token(&second, now));
    }

    #[test]
    fn full_buckets_are_swept_after_churn() {
        let mut budget = PeerErrorBudget::new();
        let start = crate::time::instant_now();
        for value in 0..50 {
            assert!(spend(&mut budget, &addr(value), start));
        }
        assert_eq!(budget.len(), 50);
        assert!(spend(
            &mut budget,
            &addr(200),
            start + SWEEP_INTERVAL + Duration::from_secs(1)
        ));
        assert_eq!(budget.len(), 1);
    }
}
