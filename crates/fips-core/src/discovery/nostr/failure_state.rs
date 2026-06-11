//! Per-peer NAT-traversal failure tracking.
//!
//! Records consecutive offer/answer signal-timeout (and other) failures
//! against each peer. Drives three operator-visible behaviors:
//!
//! - **WARN log rate-limit (B1).** Suppresses repeat WARN lines for the
//!   same peer inside a configurable window; subsequent failures inside
//!   the window log at DEBUG instead.
//! - **Extended cooldown (B2).** Once a peer accumulates
//!   `failure_streak_threshold` consecutive failures, the next
//!   `extended_cooldown_secs` worth of attempts are suppressed by pushing
//!   the retry timer out, capping how aggressively a public-test node can
//!   hammer Nostr relays with offers to dead peers.
//! - **Stale-advert eviction (B6).** At streak threshold, the daemon
//!   actively re-fetches the peer's advert; outcomes (`Evicted`,
//!   `Refreshed`, `SameAdvert`, `Skipped`) feed back into the cache so
//!   peers that have actually disappeared stop being retried after
//!   eviction (`prune_advert_cache` semantics).
//!
//! Also stores last-observed clock skew (from B5a) so operators can
//! surface it via `fipsctl show peers` (B3).

use std::collections::HashMap;
use std::sync::Mutex;

use nostr::nips::nip19::ToBech32;
use nostr::prelude::PublicKey;

use crate::PeerIdentity;

/// Canonical Nostr peer key used by traversal liveness internals.
///
/// Npub/hex strings are edge formats. The failure map stores the raw public-key
/// bytes so hex and npub spellings of the same peer cannot create separate
/// liveness/cooldown records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct NostrPeerKey([u8; PublicKey::LEN]);

impl NostrPeerKey {
    pub(super) fn parse(peer: &str) -> Result<Self, nostr::key::Error> {
        Ok(Self::from_public_key(PublicKey::parse(peer)?))
    }

    pub(super) fn from_public_key(pubkey: PublicKey) -> Self {
        Self::from_public_key_ref(&pubkey)
    }

    pub(super) fn from_public_key_ref(pubkey: &PublicKey) -> Self {
        Self(pubkey.to_bytes())
    }

    pub(super) fn from_peer_identity(peer: PeerIdentity) -> Self {
        Self(peer.pubkey().serialize())
    }

    pub(super) fn npub(self) -> String {
        PublicKey::from_byte_array(self.0)
            .to_bech32()
            .expect("npub encoding cannot fail for 32-byte public keys")
    }
}

/// One peer's failure-tracking state.
#[derive(Debug, Clone)]
pub(super) struct PeerFailureRecord {
    /// Number of consecutive failures since the last success (or fresh
    /// advert that reset the streak).
    pub consecutive_failures: u32,
    /// When this entry was last touched, used for size-cap eviction.
    pub last_failure_at_ms: u64,
    /// When the last WARN was emitted for this peer; controls WARN
    /// rate-limit (B1).
    pub last_warn_at_ms: Option<u64>,
    /// When the extended cooldown was applied; while
    /// `cooldown_until_ms.is_some_and(|t| t > now)`, retries are
    /// suppressed.
    pub cooldown_until_ms: Option<u64>,
    /// Most recent NTP-style skew estimate (B5a), in ms (positive =
    /// peer ahead of us). `None` if the peer hasn't successfully
    /// answered an offer with `offerReceivedAt` populated, or if
    /// successful traversal cleared the streak (we keep the last-seen
    /// skew, but only on records that are still in the map).
    pub last_observed_skew_ms: Option<i64>,
}

impl PeerFailureRecord {
    fn new(now_ms: u64) -> Self {
        Self {
            consecutive_failures: 0,
            last_failure_at_ms: now_ms,
            last_warn_at_ms: None,
            cooldown_until_ms: None,
            last_observed_skew_ms: None,
        }
    }
}

/// What the lifecycle layer should do based on the recorded failure.
#[derive(Debug, Clone, Copy)]
pub(super) struct FailureDecision {
    /// Updated streak count (post-increment).
    pub consecutive_failures: u32,
    /// True iff lifecycle should log at WARN; false → log at DEBUG.
    pub should_warn: bool,
    /// If set, retry_after_ms for this peer should not fire before this
    /// wall-clock ms.
    pub cooldown_until_ms: Option<u64>,
    /// True only on the streak-threshold-crossing transition. Lifecycle
    /// should run a one-shot stale-advert check (B6) when this fires.
    pub crossed_threshold: bool,
}

pub(super) struct FailureState {
    inner: Mutex<HashMap<NostrPeerKey, PeerFailureRecord>>,
    threshold: u32,
    extended_cooldown_ms: u64,
    warn_log_interval_ms: u64,
    max_entries: usize,
}

impl FailureState {
    pub(super) fn new(
        threshold: u32,
        extended_cooldown_secs: u64,
        warn_log_interval_secs: u64,
        max_entries: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            threshold,
            extended_cooldown_ms: extended_cooldown_secs.saturating_mul(1000),
            warn_log_interval_ms: warn_log_interval_secs.saturating_mul(1000),
            max_entries,
        }
    }

    /// Record a traversal failure against `peer`. Returns the resulting
    /// FailureDecision for the lifecycle layer to act on.
    pub(super) fn record_failure(&self, peer: NostrPeerKey, now_ms: u64) -> FailureDecision {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        let entry = map
            .entry(peer)
            .or_insert_with(|| PeerFailureRecord::new(now_ms));
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_failure_at_ms = now_ms;

        let crossed_threshold = entry.consecutive_failures == self.threshold;
        let cooldown_until_ms = if entry.consecutive_failures >= self.threshold {
            let cooldown = now_ms.saturating_add(self.extended_cooldown_ms);
            entry.cooldown_until_ms = Some(cooldown);
            Some(cooldown)
        } else {
            None
        };

        let should_warn = !matches!(
            entry.last_warn_at_ms,
            Some(last) if now_ms.saturating_sub(last) < self.warn_log_interval_ms
        );
        if should_warn {
            entry.last_warn_at_ms = Some(now_ms);
        }

        let decision = FailureDecision {
            consecutive_failures: entry.consecutive_failures,
            should_warn,
            cooldown_until_ms,
            crossed_threshold,
        };

        if map.len() > self.max_entries {
            evict_oldest(&mut map, self.max_entries);
        }

        decision
    }

    /// Record that a path completed traversal/handshake but later died under
    /// link liveness.
    ///
    /// This is path-level evidence, not peer-level evidence: it is useful for
    /// logs and stale-advert refresh thresholding, but it must not install the
    /// peer-wide traversal cooldown used for repeated failed offers. Fallback
    /// transports should continue carrying traffic while direct candidates are
    /// probed in the background.
    pub(super) fn record_unstable_path(&self, peer: NostrPeerKey, now_ms: u64) -> FailureDecision {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        let entry = map
            .entry(peer)
            .or_insert_with(|| PeerFailureRecord::new(now_ms));

        let previous = entry.consecutive_failures;
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_failure_at_ms = now_ms;

        let crossed_threshold =
            previous < self.threshold && entry.consecutive_failures >= self.threshold;

        let should_warn = !matches!(
            entry.last_warn_at_ms,
            Some(last) if now_ms.saturating_sub(last) < self.warn_log_interval_ms
        );
        if should_warn {
            entry.last_warn_at_ms = Some(now_ms);
        }

        let decision = FailureDecision {
            consecutive_failures: entry.consecutive_failures,
            should_warn,
            cooldown_until_ms: entry.cooldown_until_ms,
            crossed_threshold,
        };

        if map.len() > self.max_entries {
            evict_oldest(&mut map, self.max_entries);
        }

        decision
    }

    /// Record a successful traversal — clears the streak and cooldown.
    /// Last-observed skew is retained until next eviction since it's
    /// useful to display in `show_peers` even for healthy peers.
    pub(super) fn record_success(&self, peer: NostrPeerKey, now_ms: u64) {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        if let Some(entry) = map.get_mut(&peer) {
            entry.consecutive_failures = 0;
            entry.cooldown_until_ms = None;
            entry.last_failure_at_ms = now_ms;
        }
        // No insert if absent — successful peers don't need a record.
    }

    /// Record an observed clock-skew estimate from a successful answer
    /// receipt (B5a). Creates an entry if needed so we can surface the
    /// skew via `show_peers` even when the peer is healthy.
    pub(super) fn note_observed_skew(&self, peer: NostrPeerKey, skew_ms: i64, now_ms: u64) {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        let entry = map
            .entry(peer)
            .or_insert_with(|| PeerFailureRecord::new(now_ms));
        entry.last_observed_skew_ms = Some(skew_ms);

        if map.len() > self.max_entries {
            evict_oldest(&mut map, self.max_entries);
        }
    }

    /// Reset streak/cooldown after a successful B6 advert refresh.
    pub(super) fn reset_streak_after_refresh(&self, peer: NostrPeerKey) {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        if let Some(entry) = map.get_mut(&peer) {
            entry.consecutive_failures = 0;
            entry.cooldown_until_ms = None;
        }
    }

    /// Record a fatal protocol mismatch against `peer` and apply
    /// `cooldown_ms` immediately (independent of the streak threshold).
    ///
    /// Returns `true` when this is a fresh mismatch entry (caller should
    /// log a one-shot WARN) or `false` if a comparable mismatch cooldown
    /// is already in place (caller should remain silent — repeat
    /// observations of the same mismatch are uninteresting).
    ///
    /// Used when the rx loop sees an unhandshakable packet (e.g.,
    /// `Unknown FMP version`) on a Nostr-adopted bootstrap transport:
    /// re-traversing the peer at the next sweep cycle is wasted effort
    /// because the peer cannot accept our handshake until one side
    /// upgrades. The cooldown is much longer than the transient-failure
    /// `extended_cooldown_ms` because the mismatch is structural.
    pub(super) fn record_protocol_mismatch(
        &self,
        peer: NostrPeerKey,
        now_ms: u64,
        cooldown_ms: u64,
    ) -> bool {
        let mut map = self.inner.lock().expect("failure-state mutex poisoned");
        let entry = map
            .entry(peer)
            .or_insert_with(|| PeerFailureRecord::new(now_ms));
        // Treat the mismatch as crossing the streak threshold so other
        // visibility paths (e.g. show_peers JSON) reflect the failed state.
        entry.consecutive_failures = entry.consecutive_failures.max(self.threshold);
        entry.last_failure_at_ms = now_ms;

        let cooldown_until = now_ms.saturating_add(cooldown_ms);
        // "Fresh" means we weren't already inside a comparable cooldown
        // window. Use the existing-cooldown's remaining time as the test
        // so that an entry shifted forward by a few seconds doesn't keep
        // re-triggering WARNs.
        let already_suppressed = entry
            .cooldown_until_ms
            .is_some_and(|t| t > now_ms && t.saturating_sub(now_ms) >= cooldown_ms / 2);
        entry.cooldown_until_ms = Some(cooldown_until);

        if map.len() > self.max_entries {
            evict_oldest(&mut map, self.max_entries);
        }

        !already_suppressed
    }

    /// Return cooldown_until_ms if the peer is currently in extended
    /// cooldown.
    pub(super) fn cooldown_until(&self, peer: NostrPeerKey, now_ms: u64) -> Option<u64> {
        let map = self.inner.lock().expect("failure-state mutex poisoned");
        map.get(&peer)
            .and_then(|e| e.cooldown_until_ms)
            .filter(|&t| t > now_ms)
    }

    /// Snapshot for `show_peers` rendering (B3).
    pub(super) fn snapshot(&self) -> Vec<(NostrPeerKey, PeerFailureRecord)> {
        let map = self.inner.lock().expect("failure-state mutex poisoned");
        map.iter().map(|(peer, rec)| (*peer, rec.clone())).collect()
    }
}

fn evict_oldest(map: &mut HashMap<NostrPeerKey, PeerFailureRecord>, target: usize) {
    if map.len() <= target {
        return;
    }
    let overflow = map.len() - target;
    let mut entries: Vec<(NostrPeerKey, u64)> = map
        .iter()
        .map(|(k, v)| (*k, v.last_failure_at_ms))
        .collect();
    entries.sort_by_key(|(_, t)| *t);
    for (k, _) in entries.into_iter().take(overflow) {
        map.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs() -> FailureState {
        // threshold=3, cooldown=10s, warn-interval=5s, cap=8
        FailureState::new(3, 10, 5, 8)
    }

    fn peer(byte: u8) -> NostrPeerKey {
        NostrPeerKey([byte; PublicKey::LEN])
    }

    #[test]
    fn first_failure_warns_and_no_cooldown() {
        let s = fs();
        let d = s.record_failure(peer(1), 1000);
        assert_eq!(d.consecutive_failures, 1);
        assert!(d.should_warn);
        assert!(d.cooldown_until_ms.is_none());
        assert!(!d.crossed_threshold);
    }

    #[test]
    fn warn_suppressed_inside_window_then_unsuppressed_after() {
        let s = fs();
        let p = peer(1);
        let d1 = s.record_failure(p, 1000);
        let d2 = s.record_failure(p, 1500);
        assert!(d1.should_warn);
        assert!(
            !d2.should_warn,
            "second failure inside 5s window must DEBUG"
        );
        // 5s warn-interval = 5000 ms; bump beyond.
        let d3 = s.record_failure(p, 1000 + 5_500);
        assert!(d3.should_warn, "after window, must WARN again");
    }

    #[test]
    fn streak_threshold_triggers_cooldown_and_signals_crossing() {
        let s = fs();
        let p = peer(1);
        let _ = s.record_failure(p, 1000);
        let _ = s.record_failure(p, 1100);
        let d3 = s.record_failure(p, 1200);
        assert_eq!(d3.consecutive_failures, 3);
        assert!(d3.crossed_threshold);
        assert_eq!(d3.cooldown_until_ms, Some(1200 + 10_000));
        // Subsequent failure does NOT re-fire crossed_threshold.
        let d4 = s.record_failure(p, 1300);
        assert!(!d4.crossed_threshold);
        assert!(d4.cooldown_until_ms.is_some());
    }

    #[test]
    fn record_success_clears_streak() {
        let s = fs();
        let p = peer(1);
        for t in [1000u64, 1100, 1200, 1300] {
            let _ = s.record_failure(p, t);
        }
        s.record_success(p, 2000);
        let d = s.record_failure(p, 3000);
        assert_eq!(d.consecutive_failures, 1, "streak reset after success");
        assert!(!d.crossed_threshold);
    }

    #[test]
    fn cooldown_until_returns_only_active_cooldowns() {
        let s = fs();
        let p = peer(1);
        for t in [1000u64, 1100, 1200] {
            let _ = s.record_failure(p, t);
        }
        // Mid-cooldown
        assert!(s.cooldown_until(p, 5_000).is_some());
        // Past cooldown
        assert!(s.cooldown_until(p, 1200 + 10_001).is_none());
    }

    #[test]
    fn note_observed_skew_creates_entry_for_healthy_peer() {
        let s = fs();
        let p = peer(1);
        s.note_observed_skew(p, 250, 1000);
        let snap = s.snapshot();
        assert_eq!(snap.len(), 1);
        let (key, rec) = &snap[0];
        assert_eq!(*key, p);
        assert_eq!(rec.last_observed_skew_ms, Some(250));
        assert_eq!(rec.consecutive_failures, 0);
    }

    #[test]
    fn peer_key_canonicalizes_hex_and_npub_spellings() {
        let public_key = nostr::Keys::generate().public_key();
        let npub = public_key.to_bech32().expect("npub");
        let hex = public_key.to_hex();

        let npub_key = NostrPeerKey::parse(&npub).expect("npub key");
        let hex_key = NostrPeerKey::parse(&hex).expect("hex key");

        assert_eq!(npub_key, hex_key);
        assert_eq!(npub_key.npub(), npub);
    }

    #[test]
    fn record_protocol_mismatch_fresh_entry_returns_true() {
        let s = fs();
        let p = peer(2);
        // 24h cooldown
        let cooldown_ms = 24 * 60 * 60 * 1000;
        assert!(
            s.record_protocol_mismatch(p, 1000, cooldown_ms),
            "first mismatch must signal fresh — caller should WARN"
        );
        assert_eq!(
            s.cooldown_until(p, 2000),
            Some(1000 + cooldown_ms),
            "cooldown applied immediately"
        );
    }

    #[test]
    fn record_protocol_mismatch_repeat_inside_window_returns_false() {
        let s = fs();
        let p = peer(2);
        let cooldown_ms = 24 * 60 * 60 * 1000;
        s.record_protocol_mismatch(p, 1000, cooldown_ms);
        // 30s later, same mismatch — caller should NOT re-WARN
        assert!(
            !s.record_protocol_mismatch(p, 31_000, cooldown_ms),
            "second mismatch inside the existing cooldown must NOT signal fresh"
        );
        // Cooldown extends forward.
        assert_eq!(s.cooldown_until(p, 32_000), Some(31_000 + cooldown_ms),);
    }

    #[test]
    fn record_protocol_mismatch_pins_streak_at_threshold() {
        let s = fs();
        let p = peer(2);
        s.record_protocol_mismatch(p, 1000, 60_000);
        // Snapshot reflects the threshold pin so show_peers renders the
        // entry as crossed-threshold.
        let snap = s.snapshot();
        let (_, rec) = snap
            .iter()
            .find(|(key, _)| *key == p)
            .expect("entry present");
        assert!(rec.consecutive_failures >= 3);
    }

    #[test]
    fn record_protocol_mismatch_after_old_cooldown_lapsed_signals_fresh() {
        let s = fs();
        let p = peer(2);
        let cooldown_ms = 24 * 60 * 60 * 1000;
        s.record_protocol_mismatch(p, 1000, cooldown_ms);
        // Far in the future after cooldown elapsed: a *new* observation
        // is fresh again so the operator gets a fresh WARN log.
        let later = 1000 + cooldown_ms + 1;
        assert!(
            s.record_protocol_mismatch(p, later, cooldown_ms),
            "after the cooldown window has elapsed, the next mismatch is fresh"
        );
    }

    #[test]
    fn size_cap_evicts_oldest_by_last_failure_at() {
        let s = fs(); // cap = 8
        for i in 0..10 {
            let _ = s.record_failure(peer(i), 1000 + i as u64);
        }
        let snap = s.snapshot();
        assert!(snap.len() <= 8, "cap not enforced: {}", snap.len());
        // Oldest two should be evicted; newer kept.
        let keys: std::collections::HashSet<_> = snap.iter().map(|(key, _)| *key).collect();
        assert!(!keys.contains(&peer(0)));
        assert!(!keys.contains(&peer(1)));
        assert!(keys.contains(&peer(9)));
    }
}
