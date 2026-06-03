//! Connection retry logic for auto-connect peers.
//!
//! When an outbound handshake fails (timeout or send error), the node can
//! automatically retry with exponential backoff. Retry state lives on Node
//! (not PeerConnection) because each retry creates a fresh connection.

use super::{Node, NodeError};
use crate::PeerIdentity;
use crate::config::PeerConfig;
use crate::identity::NodeAddr;
use tracing::{debug, info, warn};

// MAX_BACKOFF_MS is now derived from config: node.retry.max_backoff_secs * 1000
const MAX_RETRY_CONNECTIONS_PER_TICK: usize = 16;
const LOCAL_ROUTE_RETRY_DELAY_MS: u64 = 2_000;
const LINK_DEAD_DIRECT_REPROBE_DELAY_MS: u64 = 2_000;

/// Tracks retry state for a peer across connection attempts.
pub struct RetryState {
    /// The peer config to use for initiating retries.
    pub peer_config: PeerConfig,

    /// Number of retries attempted so far.
    pub retry_count: u32,

    /// Timestamp (Unix ms) when the next retry should be attempted.
    pub retry_after_ms: u64,

    /// Whether this is an auto-reconnect (unlimited retries, ignores max_retries).
    pub reconnect: bool,

    /// Optional absolute expiry for this retry entry (Unix ms).
    ///
    /// When set, retries are dropped after this point even if reconnect logic
    /// would otherwise continue.
    pub expires_at_ms: Option<u64>,
}

impl RetryState {
    /// Create a new retry state for a peer.
    pub fn new(peer_config: PeerConfig) -> Self {
        Self {
            peer_config,
            retry_count: 0,
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        }
    }

    /// Calculate the backoff delay in milliseconds for the current retry count.
    ///
    /// Uses exponential backoff: `base_interval_ms * 2^retry_count`,
    /// capped at `MAX_BACKOFF_MS`.
    pub fn backoff_ms(&self, base_interval_ms: u64, max_backoff_ms: u64) -> u64 {
        let multiplier = 1u64.checked_shl(self.retry_count).unwrap_or(u64::MAX);
        base_interval_ms
            .saturating_mul(multiplier)
            .min(max_backoff_ms)
    }
}

impl Node {
    /// Schedule a retry for a failed outbound connection, if applicable.
    ///
    /// Only schedules if the peer is an auto-connect peer and max retries
    /// have not been exhausted (unless `reconnect` is true, which retries
    /// indefinitely). An active peer suppresses retry only when it is already
    /// on a fresh configured direct path; fallback paths keep bounded direct
    /// refresh retries alive.
    pub(super) fn schedule_retry(&mut self, node_addr: NodeAddr, now_ms: u64) {
        let retry_cfg = &self.config.node.retry;
        let max_retries = retry_cfg.max_retries;
        if max_retries == 0 {
            return;
        }

        let peer_config = self
            .retry_pending
            .get(&node_addr)
            .map(|state| state.peer_config.clone())
            .or_else(|| {
                self.config
                    .auto_connect_peers()
                    .find(|pc| {
                        PeerIdentity::from_npub(&pc.npub)
                            .map(|id| *id.node_addr() == node_addr)
                            .unwrap_or(false)
                    })
                    .cloned()
            });

        if self.peers.contains_key(&node_addr) {
            let Some(pc) = peer_config.as_ref() else {
                return;
            };
            if !self.active_peer_should_keep_direct_retry(&node_addr, pc) {
                return;
            }
        }

        let base_interval_ms = retry_cfg.base_interval_secs * 1000;
        let max_backoff_ms = retry_cfg.max_backoff_secs * 1000;
        let peer_name = self.peer_display_name(&node_addr);

        if let Some(state) = self.retry_pending.get_mut(&node_addr) {
            // Already tracking — increment
            state.retry_count += 1;
            if !state.reconnect && state.retry_count > max_retries {
                info!(
                    peer = %peer_name,
                    attempts = state.retry_count,
                    "Max retries exhausted, giving up on peer"
                );
                self.retry_pending.remove(&node_addr);
                return;
            }
            let delay = state.backoff_ms(base_interval_ms, max_backoff_ms);
            state.retry_after_ms = state.retry_after_ms.max(now_ms + delay);
            debug!(
                peer = %peer_name,
                retry = state.retry_count,
                reconnect = state.reconnect,
                delay_secs = delay / 1000,
                "Scheduling connection retry"
            );
        } else {
            if let Some(pc) = peer_config {
                let mut state = RetryState::new(pc);
                state.retry_count = 1;
                state.reconnect = true;
                let delay = state.backoff_ms(base_interval_ms, max_backoff_ms);
                state.retry_after_ms = now_ms + delay;
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    delay_secs = delay / 1000,
                    "First connection attempt failed, scheduling retry"
                );
                self.retry_pending.insert(node_addr, state);
            }
            // If not found in auto_connect_peers, no retry (one-shot connection)
        }
    }

    /// Schedule a quick retry for local underlay route/socket failures.
    ///
    /// These errors mean the local OS could not send at all during a network
    /// transition. They should not count as peer failures or increase the
    /// exponential retry count.
    pub(super) fn schedule_local_route_retry(&mut self, node_addr: NodeAddr, now_ms: u64) {
        let retry_cfg = &self.config.node.retry;
        if retry_cfg.max_retries == 0 {
            return;
        }

        let peer_config = self
            .retry_pending
            .get(&node_addr)
            .map(|state| state.peer_config.clone())
            .or_else(|| {
                self.config
                    .auto_connect_peers()
                    .find(|pc| {
                        PeerIdentity::from_npub(&pc.npub)
                            .map(|id| *id.node_addr() == node_addr)
                            .unwrap_or(false)
                    })
                    .cloned()
            });

        if self.peers.contains_key(&node_addr) {
            let Some(pc) = peer_config.as_ref() else {
                return;
            };
            if !self.active_peer_should_keep_direct_retry(&node_addr, pc) {
                return;
            }
        }

        let retry_after_ms = now_ms.saturating_add(LOCAL_ROUTE_RETRY_DELAY_MS);
        let peer_name = self.peer_display_name(&node_addr);

        if let Some(state) = self.retry_pending.get_mut(&node_addr) {
            state.reconnect = true;
            state.retry_after_ms = retry_after_ms;
            debug!(
                peer = %peer_name,
                retry = state.retry_count,
                delay_ms = LOCAL_ROUTE_RETRY_DELAY_MS,
                "Local route unavailable, scheduling short retry"
            );
        } else if let Some(pc) = peer_config {
            let mut state = RetryState::new(pc);
            state.reconnect = true;
            state.retry_after_ms = retry_after_ms;
            debug!(
                peer = %peer_name,
                delay_ms = LOCAL_ROUTE_RETRY_DELAY_MS,
                "Local route unavailable on first attempt, scheduling short retry"
            );
            self.retry_pending.insert(node_addr, state);
        }
    }

    pub(super) fn schedule_retry_after_error(
        &mut self,
        node_addr: NodeAddr,
        now_ms: u64,
        error: &NodeError,
    ) {
        if error.is_local_route_unavailable() {
            self.schedule_local_route_retry(node_addr, now_ms);
        } else {
            self.schedule_retry(node_addr, now_ms);
        }
    }

    /// Schedule auto-reconnect for a peer removed by MMP dead timeout.
    ///
    /// Looks up the peer in auto-connect config and checks `auto_reconnect`.
    /// If enabled, feeds the peer into the retry system with unlimited retries.
    ///
    /// If a retry entry already exists (e.g. from a previous failed handshake
    /// attempt during an earlier reconnect cycle), the existing retry count is
    /// preserved and incremented rather than reset to zero. This ensures
    /// exponential backoff accumulates across repeated link-dead events instead
    /// of resetting to the base interval on every peer removal.
    pub(super) fn schedule_reconnect(&mut self, node_addr: NodeAddr, now_ms: u64) {
        // Find peer in auto-connect config
        let peer_config = self
            .config
            .auto_connect_peers()
            .find(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .map(|id| *id.node_addr() == node_addr)
                    .unwrap_or(false)
            })
            .cloned();

        let Some(pc) = peer_config else {
            return; // Not an auto-connect peer, no reconnect
        };

        if !pc.auto_reconnect {
            debug!(
                peer = %self.peer_display_name(&node_addr),
                "Auto-reconnect disabled for peer, skipping"
            );
            return;
        }

        let base_interval_ms = self.config.node.retry.base_interval_secs * 1000;
        let max_backoff_ms = self.config.node.retry.max_backoff_secs * 1000;
        let peer_name = self.peer_display_name(&node_addr);

        // If we already have accumulated backoff from previous failed attempts,
        // preserve and bump it rather than resetting to zero. This prevents the
        // exponential backoff from being discarded on each link-dead cycle.
        if let Some(state) = self.retry_pending.get_mut(&node_addr) {
            state.reconnect = true;
            state.retry_count += 1;
            let delay = state.backoff_ms(base_interval_ms, max_backoff_ms);
            state.retry_after_ms = state.retry_after_ms.max(now_ms + delay);
            debug!(
                peer = %peer_name,
                retry = state.retry_count,
                delay_secs = delay / 1000,
                "Scheduling auto-reconnect after link-dead removal (backoff preserved)"
            );
            return;
        }

        let mut state = RetryState::new(pc);
        state.reconnect = true;
        let delay = state.backoff_ms(base_interval_ms, max_backoff_ms);
        state.retry_after_ms = now_ms + delay;

        debug!(
            peer = %peer_name,
            delay_secs = delay / 1000,
            "Scheduling auto-reconnect after link-dead removal"
        );

        self.retry_pending.insert(node_addr, state);
    }

    /// Schedule a quick direct re-probe after link liveness removes a path.
    ///
    /// Link-dead means the currently selected path went quiet, not that the
    /// peer or every candidate should be penalized. Keep fallback/session
    /// routing free to carry traffic, but make the direct retry loop eligible
    /// again quickly instead of preserving old traversal cooldowns or
    /// exponential backoff from this dead path.
    pub(super) fn schedule_link_dead_reprobe(&mut self, node_addr: NodeAddr, now_ms: u64) {
        let retry_cfg = &self.config.node.retry;
        if retry_cfg.max_retries == 0 {
            return;
        }

        let peer_config = self
            .retry_pending
            .get(&node_addr)
            .map(|state| state.peer_config.clone())
            .or_else(|| {
                self.config
                    .auto_connect_peers()
                    .find(|pc| {
                        PeerIdentity::from_npub(&pc.npub)
                            .map(|id| *id.node_addr() == node_addr)
                            .unwrap_or(false)
                    })
                    .cloned()
            });

        let Some(peer_config) = peer_config else {
            return;
        };

        if !peer_config.auto_reconnect {
            debug!(
                peer = %self.peer_display_name(&node_addr),
                "Auto-reconnect disabled for peer, skipping link-dead direct re-probe"
            );
            return;
        }

        let retry_after_ms = now_ms.saturating_add(LINK_DEAD_DIRECT_REPROBE_DELAY_MS);
        let peer_name = self.peer_display_name(&node_addr);
        let state = self
            .retry_pending
            .entry(node_addr)
            .or_insert_with(|| RetryState::new(peer_config.clone()));
        state.peer_config = peer_config;
        state.reconnect = true;
        state.retry_count = 0;
        state.retry_after_ms = retry_after_ms;
        state.expires_at_ms = None;

        debug!(
            peer = %peer_name,
            delay_ms = LINK_DEAD_DIRECT_REPROBE_DELAY_MS,
            "Scheduling quick direct re-probe after link-dead removal"
        );
    }

    /// Record a traversal/recent-endpoint path that authenticated but then
    /// died under MMP liveness.
    ///
    /// Link-dead is path evidence, not peer evidence: it should refresh stale
    /// adverts and diagnostics, but it must not pin a configured peer behind a
    /// long Nostr traversal cooldown while mesh/fallback traffic continues.
    pub(super) async fn record_link_dead_path_failure(
        &mut self,
        node_addr: &NodeAddr,
        now_ms: u64,
    ) {
        let peer_config = self
            .config
            .auto_connect_peers()
            .find(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .map(|id| id.node_addr() == node_addr)
                    .unwrap_or(false)
            })
            .cloned();
        let Some(peer_config) = peer_config else {
            return;
        };

        if !self.active_peer_uses_traversal_path(node_addr, &peer_config) {
            return;
        }

        if self.rx_loop_maintenance_timed_out_recently() {
            debug!(
                peer = %self.peer_display_name(node_addr),
                npub = %peer_config.npub,
                "Skipping traversal instability penalty after recent rx-loop maintenance timeout"
            );
            return;
        }

        let Some(bootstrap) = self.nostr_discovery.clone() else {
            return;
        };

        let decision = bootstrap.record_unstable_path(&peer_config.npub, now_ms);
        let cooldown_secs = decision
            .cooldown_until_ms
            .map(|t| t.saturating_sub(now_ms) / 1000);
        if decision.should_warn {
            warn!(
                peer = %self.peer_display_name(node_addr),
                npub = %peer_config.npub,
                consecutive_failures = decision.consecutive_failures,
                cooldown_secs = ?cooldown_secs,
                "Traversal path marked unstable after link-dead timeout"
            );
        } else {
            debug!(
                peer = %self.peer_display_name(node_addr),
                npub = %peer_config.npub,
                consecutive_failures = decision.consecutive_failures,
                cooldown_secs = ?cooldown_secs,
                "Traversal path marked unstable after link-dead timeout"
            );
        }

        if decision.crossed_threshold {
            bootstrap
                .request_advert_stale_check(peer_config.npub.clone())
                .await;
        }

        if decision.cooldown_until_ms.is_some() {
            debug!(
                peer = %self.peer_display_name(node_addr),
                npub = %peer_config.npub,
                "Ignoring traversal cooldown for link-dead path; direct re-probe remains scheduled separately"
            );
        }
    }

    /// Process pending retries whose time has arrived.
    ///
    /// For each due retry, initiates a fresh connection attempt. The retry
    /// entry stays in `retry_pending` until the connection succeeds (cleared
    /// in `promote_connection`) or max retries are exhausted (cleared in
    /// `schedule_retry`).
    pub(super) async fn process_pending_retries(&mut self, now_ms: u64) {
        if self.retry_pending.is_empty() {
            return;
        }

        let expired: Vec<NodeAddr> = self
            .retry_pending
            .iter()
            .filter_map(|(addr, state)| {
                state
                    .expires_at_ms
                    .filter(|expires_at_ms| now_ms >= *expires_at_ms)
                    .map(|_| *addr)
            })
            .collect();
        for node_addr in expired {
            self.retry_pending.remove(&node_addr);
            info!(
                peer = %self.peer_display_name(&node_addr),
                "Retry window expired, dropping pending retry state"
            );
        }
        if self.retry_pending.is_empty() {
            return;
        }

        // Collect retries that are due
        let due: Vec<NodeAddr> = self
            .retry_pending
            .iter()
            .filter(|(_, state)| now_ms >= state.retry_after_ms)
            .map(|(addr, _)| *addr)
            .collect();
        let deferred = due.len().saturating_sub(MAX_RETRY_CONNECTIONS_PER_TICK);
        if deferred > 0 {
            debug!(
                due = due.len(),
                processing = MAX_RETRY_CONNECTIONS_PER_TICK,
                deferred,
                "Retry processing budget exhausted; deferring remaining peers"
            );
        }

        for node_addr in due.into_iter().take(MAX_RETRY_CONNECTIONS_PER_TICK) {
            if self.peers.contains_key(&node_addr) {
                if !self.outbound_direct_refresh_admission_check() {
                    debug!(
                        peer = %self.peer_display_name(&node_addr),
                        retry_pending = self.retry_pending.len(),
                        "Suppressing active-peer direct refresh retry: at connection/link capacity"
                    );
                    continue;
                }

                let Some(peer_config) = self
                    .retry_pending
                    .get(&node_addr)
                    .map(|state| state.peer_config.clone())
                else {
                    continue;
                };

                if !self.active_peer_should_keep_direct_retry(&node_addr, &peer_config) {
                    self.retry_pending.remove(&node_addr);
                    continue;
                }

                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "Attempting direct-path retry while fallback peer remains active"
                );

                if let Some(bootstrap) = self.nostr_discovery.clone() {
                    bootstrap
                        .request_advert_stale_check(peer_config.npub.clone())
                        .await;
                }

                match self
                    .initiate_active_peer_alternative_connection(&peer_config)
                    .await
                {
                    Ok(true) => {
                        let hs_timeout_ms =
                            self.config.node.rate_limit.handshake_timeout_secs * 1000;
                        if let Some(state) = self.retry_pending.get_mut(&node_addr) {
                            state.retry_after_ms = now_ms + hs_timeout_ms;
                        }
                        debug!(
                            peer = %self.peer_display_name(&node_addr),
                            "Direct-path retry initiated while preserving active fallback peer"
                        );
                    }
                    Ok(false) => {
                        if self.active_peer_should_keep_direct_retry(&node_addr, &peer_config) {
                            self.schedule_retry(node_addr, now_ms);
                        } else {
                            self.retry_pending.remove(&node_addr);
                        }
                    }
                    Err(e) => {
                        warn!(
                            peer = %self.peer_display_name(&node_addr),
                            error = %e,
                            "Direct-path retry initiation failed while fallback peer remains active"
                        );
                        if matches!(e, NodeError::NoTransportForType(_))
                            && let Some(bootstrap) = self.nostr_discovery.clone()
                        {
                            bootstrap
                                .request_advert_stale_check(peer_config.npub.clone())
                                .await;
                        }
                        self.schedule_retry_after_error(node_addr, now_ms, &e);
                    }
                }
                continue;
            }

            if !self.outbound_admission_check() {
                debug!(
                    peers = self.peers.len(),
                    max_peers = self.max_peers,
                    retry_pending = self.retry_pending.len(),
                    "Suppressing auto-reconnect retry: at capacity"
                );
                continue;
            }

            let state = match self.retry_pending.get(&node_addr) {
                Some(s) => s,
                None => continue,
            };

            debug!(
                peer = %self.peer_display_name(&node_addr),
                retry = state.retry_count,
                "Attempting connection retry"
            );

            let peer_config = state.peer_config.clone();

            // Ask the Nostr runtime to refresh stale overlay adverts without
            // blocking this maintenance tick; retry cadence can otherwise stall
            // daemon status/control traffic behind relay fetch timeouts.
            if let Some(bootstrap) = self.nostr_discovery.clone() {
                bootstrap
                    .request_advert_stale_check(peer_config.npub.clone())
                    .await;
            }

            match self.initiate_peer_retry_connection(&peer_config).await {
                Ok(()) => {
                    // Push retry_after_ms past the handshake timeout window so
                    // we don't re-fire on the next tick. If the handshake
                    // succeeds, promote_connection() clears retry_pending. If
                    // it times out, check_timeouts() calls schedule_retry()
                    // which bumps the counter and applies proper backoff.
                    let hs_timeout_ms = self.config.node.rate_limit.handshake_timeout_secs * 1000;
                    if let Some(state) = self.retry_pending.get_mut(&node_addr) {
                        state.retry_after_ms = now_ms + hs_timeout_ms;
                    }
                    debug!(
                        peer = %self.peer_display_name(&node_addr),
                        "Retry connection initiated, suppressing re-fire for {}s",
                        self.config.node.rate_limit.handshake_timeout_secs,
                    );
                }
                Err(e) => {
                    warn!(
                        peer = %self.peer_display_name(&node_addr),
                        error = %e,
                        "Retry connection initiation failed"
                    );
                    // No-transport failures usually mean the cached overlay
                    // advert is stale (peer rebound NAT, switched relay, etc.).
                    // The advert cache is read-only inside fetch_advert, so
                    // every retry returns the same dead address until the
                    // entry expires. Force a re-fetch so the next retry tick
                    // picks up fresh endpoints.
                    if matches!(e, NodeError::NoTransportForType(_))
                        && let Some(bootstrap) = self.nostr_discovery.clone()
                    {
                        bootstrap
                            .request_advert_stale_check(peer_config.npub.clone())
                            .await;
                    }
                    // Immediate failure counts as an attempt — schedule next retry
                    // (reconnect flag is preserved on existing retry_pending entry)
                    self.schedule_retry_after_error(node_addr, now_ms, &e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerConfig;

    const TEST_MAX_BACKOFF_MS: u64 = 300_000;

    #[test]
    fn test_backoff_exponential() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 0,
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        };
        // base = 5000ms
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 5000); // 5s * 2^0

        let state = RetryState {
            retry_count: 1,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 10_000); // 5s * 2^1

        let state = RetryState {
            retry_count: 2,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 20_000); // 5s * 2^2

        let state = RetryState {
            retry_count: 3,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 40_000); // 5s * 2^3

        let state = RetryState {
            retry_count: 4,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 80_000); // 5s * 2^4
    }

    #[test]
    fn test_backoff_cap() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 20, // 2^20 * 5000 would be huge
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        };
        assert_eq!(
            state.backoff_ms(5000, TEST_MAX_BACKOFF_MS),
            TEST_MAX_BACKOFF_MS
        );
    }

    #[test]
    fn test_backoff_zero_base() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 3,
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        };
        assert_eq!(state.backoff_ms(0, TEST_MAX_BACKOFF_MS), 0);
    }
}
