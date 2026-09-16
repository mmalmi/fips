//! Shared bounded packet/byte admission for non-financial allowances.
use fips_core::{NodeAddr, node::TokenBucket};
use serde::Serialize;
use std::{collections::HashMap, time::Duration};
use tokio::time::Instant;

const MAX_PEERS: usize = 64;
const PEER_RETENTION: Duration = Duration::from_secs(60);
const GLOBAL_BURST: u32 = 65_536;
const GLOBAL_RATE: f64 = 16_384.0;
const PEER_BURST: u32 = 16_384;
const PEER_RATE: f64 = 4_096.0;
// Bound packet processing as well as bytes for the smallest handshake frames.
pub(crate) const MIN_CHARGE: u32 = 256;

#[derive(Clone, Debug, Default, Serialize)]
pub struct UnpaidStats {
    pub admitted_packets: u64,
    pub admitted_session_bytes: u64,
    pub charged_units: u64,
    pub rate_denied: u64,
    pub peer_capacity_denied: u64,
    pub tracked_peers: usize,
}

#[derive(Debug)]
struct PeerBudget {
    bucket: TokenBucket,
    last_used: Instant,
}

#[derive(Debug)]
pub(crate) struct UnpaidBudget {
    global: TokenBucket,
    peer_burst: u32,
    peer_rate: f64,
    peers: HashMap<NodeAddr, PeerBudget>,
    stats: UnpaidStats,
}

impl UnpaidBudget {
    pub(crate) fn new() -> Self {
        Self::with_rates(GLOBAL_BURST, GLOBAL_RATE, PEER_BURST, PEER_RATE)
    }

    pub(crate) fn for_returns() -> Self {
        Self::with_rates(8_192, 4_096.0, 2_048, 1_024.0)
    }

    fn with_rates(global_burst: u32, global_rate: f64, peer_burst: u32, peer_rate: f64) -> Self {
        Self {
            global: TokenBucket::with_params(global_burst, global_rate),
            peer_burst,
            peer_rate,
            peers: HashMap::new(),
            stats: UnpaidStats::default(),
        }
    }

    pub(crate) fn admit(&mut self, peer: NodeAddr, bytes: usize) -> bool {
        self.admit_at(peer, bytes, Instant::now())
    }

    pub(crate) fn admit_at(&mut self, peer: NodeAddr, bytes: usize, now: Instant) -> bool {
        // A retired peer would already have completely refilled (four seconds).
        // Disconnects and claimed source/destination changes do not erase debt.
        self.peers
            .retain(|_, p| now.saturating_duration_since(p.last_used) < PEER_RETENTION);
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_PEERS {
            self.stats.peer_capacity_denied = self.stats.peer_capacity_denied.saturating_add(1);
            return false;
        }
        let Ok(bytes) = u32::try_from(bytes) else {
            return false;
        };
        let charge = bytes.max(MIN_CHARGE);
        // Commit both budgets together. An exhausted peer must not burn another
        // neighbor's global allowance, and global denial must not allocate state.
        let mut global = self.global.clone();
        let mut local = self
            .peers
            .get(&peer)
            .map(|p| p.bucket.clone())
            .unwrap_or_else(|| TokenBucket::with_params(self.peer_burst, self.peer_rate));
        if !local.try_acquire_n(charge) || !global.try_acquire_n(charge) {
            self.stats.rate_denied = self.stats.rate_denied.saturating_add(1);
            return false;
        }
        self.global = global;
        self.peers.insert(
            peer,
            PeerBudget {
                bucket: local,
                last_used: now,
            },
        );
        self.stats.admitted_packets = self.stats.admitted_packets.saturating_add(1);
        self.stats.admitted_session_bytes = self
            .stats
            .admitted_session_bytes
            .saturating_add(u64::from(bytes));
        self.stats.charged_units = self.stats.charged_units.saturating_add(u64::from(charge));
        true
    }

    pub(crate) fn stats(&self) -> UnpaidStats {
        UnpaidStats {
            tracked_peers: self.peers.len(),
            ..self.stats.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(n: u16) -> NodeAddr {
        let mut bytes = [0; 16];
        bytes[..2].copy_from_slice(&n.to_be_bytes());
        NodeAddr::from_bytes(bytes)
    }

    #[test]
    fn a_full_peer_does_not_drain_the_aggregate_budget() {
        let mut budget = UnpaidBudget::new();
        budget.global = TokenBucket::with_params(4_096, 0.0);
        budget.peers.insert(
            peer(1),
            PeerBudget {
                bucket: TokenBucket::with_params(1_024, 0.0),
                last_used: Instant::now(),
            },
        );
        assert!(budget.admit(peer(1), 1_024));
        for _ in 0..100 {
            assert!(!budget.admit(peer(1), 1));
        }
        assert!(budget.admit(peer(2), 2_048));
        assert!(budget.admit(peer(2), 1_024));
        assert!(!budget.admit(peer(3), 1));
        assert_eq!(budget.stats().tracked_peers, 2);
        assert_eq!(budget.stats().charged_units, 4_096);
    }

    #[test]
    fn identity_churn_cannot_reset_global_limits_or_grow_state() {
        let mut budget = UnpaidBudget::new();
        budget.global = TokenBucket::with_params(2_048, 0.0);
        for n in 0..8 {
            assert!(budget.admit(peer(n), 1));
        }
        for n in 8..1_000 {
            assert!(!budget.admit(peer(n), 1));
        }
        assert_eq!(budget.stats().admitted_session_bytes, 8);
        assert_eq!(budget.stats().charged_units, 2_048);
        assert_eq!(budget.stats().tracked_peers, 8);
    }

    #[test]
    fn live_peer_capacity_fails_closed_and_only_idle_entries_retire() {
        let mut budget = UnpaidBudget::new();
        budget.global = TokenBucket::with_params(65_536, 0.0);
        let now = Instant::now();
        for n in 0..64 {
            assert!(budget.admit_at(peer(n), 80, now));
        }
        assert!(!budget.admit_at(peer(64), 80, now));
        assert_eq!(budget.stats().tracked_peers, 64);
        let later = now + PEER_RETENTION;
        assert!(budget.admit_at(peer(64), 80, later));
        assert_eq!(budget.stats().tracked_peers, 1);
        assert_eq!(budget.stats().charged_units, 65 * 256);
    }

    #[tokio::test]
    async fn an_exhausted_neighbor_recovers_without_recreating_its_budget() {
        let mut budget = UnpaidBudget::new();
        // The production clocks and buckets must replenish together; no new
        // connection, identity, claimed source or destination is needed.
        let mut denied = false;
        for _ in 0..1_000 {
            if !budget.admit(peer(1), 256) {
                denied = true;
                break;
            }
        }
        assert!(denied);
        let admitted = budget.stats().admitted_packets;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(budget.admit(peer(1), 256));
        assert_eq!(budget.stats().tracked_peers, 1);
        assert_eq!(budget.stats().admitted_packets, admitted + 1);
    }
}
