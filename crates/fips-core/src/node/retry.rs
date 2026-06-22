//! Connection retry logic for auto-connect peers.
//!
//! When an outbound handshake fails (timeout or send error), the node can
//! automatically retry with exponential backoff. Retry state lives on Node
//! (not PeerConnection) because each retry creates a fresh connection.

use super::{Node, NodeError};
use crate::PeerIdentity;
use crate::config::PeerConfig;
use crate::identity::NodeAddr;
use std::collections::HashMap;
use tracing::{debug, info, warn};

// MAX_BACKOFF_MS is now derived from config: node.retry.max_backoff_secs * 1000
const MAX_RETRY_CONNECTIONS_PER_TICK: usize = 16;
const MAX_ACTIVE_DIRECT_REFRESH_RETRIES_PER_TICK: usize = 2;
const LOCAL_ROUTE_RETRY_DELAY_MS: u64 = 2_000;
const LINK_DEAD_DIRECT_REPROBE_DELAY_MS: u64 = 500;
const LINK_DEAD_DIRECT_REPROBE_JITTER_MS: u64 = 1_000;
const QUIET_TRAVERSAL_DIRECT_REFRESH_JITTER_MS: u64 = 10_000;
const ACTIVE_DIRECT_REFRESH_NO_TRANSPORT_COOLDOWN_MS: u64 = 30_000;

fn node_addr_jitter_ms(node_addr: &NodeAddr, max_ms: u64) -> u64 {
    let bytes = node_addr.as_bytes();
    let seed = u16::from(bytes[0]) << 8 | u16::from(bytes[1]);
    u64::from(seed) % (max_ms + 1)
}

fn link_dead_reprobe_jitter_ms(node_addr: &NodeAddr) -> u64 {
    node_addr_jitter_ms(node_addr, LINK_DEAD_DIRECT_REPROBE_JITTER_MS)
}

fn quiet_traversal_refresh_jitter_ms(node_addr: &NodeAddr) -> u64 {
    node_addr_jitter_ms(node_addr, QUIET_TRAVERSAL_DIRECT_REFRESH_JITTER_MS)
}

/// Tracks retry state for a peer across connection attempts.
#[derive(Debug)]
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

/// Retry entries waiting for reconnect or direct-path refresh.
#[derive(Debug, Default)]
pub(in crate::node) struct PendingRouteRetries {
    entries: HashMap<NodeAddr, RetryState>,
}

impl PendingRouteRetries {
    pub(in crate::node) fn insert(
        &mut self,
        node_addr: NodeAddr,
        state: RetryState,
    ) -> Option<RetryState> {
        self.entries.insert(node_addr, state)
    }

    pub(in crate::node) fn remove(&mut self, node_addr: &NodeAddr) -> Option<RetryState> {
        self.entries.remove(node_addr)
    }

    pub(in crate::node) fn get(&self, node_addr: &NodeAddr) -> Option<&RetryState> {
        self.entries.get(node_addr)
    }

    pub(in crate::node) fn get_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut RetryState> {
        self.entries.get_mut(node_addr)
    }

    pub(in crate::node) fn contains_key(&self, node_addr: &NodeAddr) -> bool {
        self.entries.contains_key(node_addr)
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(in crate::node) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(in crate::node) fn iter(&self) -> impl Iterator<Item = (&NodeAddr, &RetryState)> {
        self.entries.iter()
    }

    pub(in crate::node) fn values(&self) -> impl Iterator<Item = &RetryState> {
        self.entries.values()
    }

    pub(in crate::node) fn get_or_insert_with(
        &mut self,
        node_addr: NodeAddr,
        f: impl FnOnce() -> RetryState,
    ) -> &mut RetryState {
        self.entries.entry(node_addr).or_insert_with(f)
    }

    pub(in crate::node) fn purge_expired(&mut self, now_ms: u64) -> Vec<NodeAddr> {
        let mut expired: Vec<NodeAddr> = self
            .entries
            .iter()
            .filter_map(|(addr, state)| {
                state
                    .expires_at_ms
                    .filter(|expires_at_ms| now_ms >= *expires_at_ms)
                    .map(|_| *addr)
            })
            .collect();
        expired.sort();
        for node_addr in &expired {
            self.entries.remove(node_addr);
        }
        expired
    }

    pub(in crate::node) fn due_for_tick<F>(
        &self,
        now_ms: u64,
        mut is_active_peer: F,
        reconnect_budget: usize,
        active_budget: usize,
    ) -> PendingRouteRetryDueTick
    where
        F: FnMut(&NodeAddr) -> bool,
    {
        let mut active_due = Vec::new();
        let mut reconnect_due = Vec::new();
        for (node_addr, state) in &self.entries {
            if now_ms < state.retry_after_ms {
                continue;
            }
            if is_active_peer(node_addr) {
                active_due.push(*node_addr);
            } else {
                reconnect_due.push(*node_addr);
            }
        }

        let retry_sort_key = |node_addr: &NodeAddr| {
            (
                self.entries
                    .get(node_addr)
                    .map(|state| state.retry_after_ms)
                    .unwrap_or(u64::MAX),
                *node_addr,
            )
        };
        active_due.sort_by_key(retry_sort_key);
        reconnect_due.sort_by_key(retry_sort_key);

        let active_total = active_due.len();
        let reconnect_total = reconnect_due.len();
        active_due.truncate(active_budget);
        reconnect_due.truncate(reconnect_budget);

        PendingRouteRetryDueTick {
            reconnect_due,
            active_due,
            reconnect_total,
            active_total,
        }
    }
}

#[derive(Debug, Default)]
pub(in crate::node) struct PendingRouteRetryDueTick {
    reconnect_due: Vec<NodeAddr>,
    active_due: Vec<NodeAddr>,
    reconnect_total: usize,
    active_total: usize,
}

impl PendingRouteRetryDueTick {
    pub(in crate::node) fn reconnect_total(&self) -> usize {
        self.reconnect_total
    }

    pub(in crate::node) fn reconnect_deferred(&self) -> usize {
        self.reconnect_total
            .saturating_sub(self.reconnect_due.len())
    }

    pub(in crate::node) fn active_total(&self) -> usize {
        self.active_total
    }

    pub(in crate::node) fn active_deferred(&self) -> usize {
        self.active_total.saturating_sub(self.active_due.len())
    }

    pub(in crate::node) fn has_deferred(&self) -> bool {
        self.reconnect_deferred() > 0 || self.active_deferred() > 0
    }

    pub(in crate::node) fn into_due_order(self) -> Vec<NodeAddr> {
        self.reconnect_due
            .into_iter()
            .chain(self.active_due)
            .collect()
    }
}

impl Node {
    fn has_established_fallback_session(&self, node_addr: &NodeAddr) -> bool {
        self.sessions
            .get(node_addr)
            .is_some_and(|entry| entry.is_established())
    }

    fn retry_is_background_direct_refresh(&self, node_addr: &NodeAddr) -> bool {
        self.peers.contains_key(node_addr) || self.has_established_fallback_session(node_addr)
    }

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
            .or_else(|| self.configured_peer(&node_addr).cloned());

        if self.peers.contains_key(&node_addr) {
            let Some(pc) = peer_config.as_ref() else {
                return;
            };
            if !self.active_peer_should_keep_direct_retry(&node_addr, pc) {
                return;
            }

            self.schedule_link_dead_reprobe(node_addr, now_ms);
            return;
        }
        if self.has_established_fallback_session(&node_addr) {
            self.schedule_link_dead_reprobe(node_addr, now_ms);
            return;
        }

        let base_interval_ms = retry_cfg.base_interval_secs * 1000;
        let max_backoff_ms = retry_cfg.max_backoff_secs * 1000;
        let peer_name = self.peer_display_name(&node_addr);

        if let Some(state) = self.retry_pending.get_mut(&node_addr) {
            // Already tracking — increment
            state.retry_count += 1;
            state.reconnect = state.reconnect || state.peer_config.auto_reconnect;
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
                state.reconnect = state.peer_config.auto_reconnect;
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
            state.reconnect = state.reconnect || state.peer_config.auto_reconnect;
            state.retry_after_ms = retry_after_ms;
            debug!(
                peer = %peer_name,
                retry = state.retry_count,
                delay_ms = LOCAL_ROUTE_RETRY_DELAY_MS,
                "Local route unavailable, scheduling short retry"
            );
        } else if let Some(pc) = peer_config {
            let mut state = RetryState::new(pc);
            state.reconnect = state.peer_config.auto_reconnect;
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

    /// Schedule a bounded direct refresh when a traversal path has missed one
    /// heartbeat but has not reached full link-dead yet.
    pub(super) fn schedule_quiet_traversal_reprobe(
        &mut self,
        node_addr: NodeAddr,
        now_ms: u64,
    ) -> bool {
        if self.config.node.retry.max_retries == 0 || self.retry_pending.contains_key(&node_addr) {
            return false;
        }

        let Some(peer_config) = self.configured_peer(&node_addr).cloned() else {
            return false;
        };
        if !peer_config.is_auto_connect() || !peer_config.auto_reconnect {
            return false;
        }

        let jitter_ms = quiet_traversal_refresh_jitter_ms(&node_addr);
        let retry_after_ms = now_ms.saturating_add(jitter_ms);
        let peer_name = self.peer_display_name(&node_addr);
        let mut state = RetryState::new(peer_config);
        state.reconnect = true;
        state.retry_count = 0;
        state.retry_after_ms = retry_after_ms;
        state.expires_at_ms = None;

        debug!(
            peer = %peer_name,
            jitter_ms,
            "Scheduling proactive direct refresh for quiet traversal path"
        );

        self.retry_pending.insert(node_addr, state);
        true
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

        let jitter_ms = link_dead_reprobe_jitter_ms(&node_addr);
        let delay_ms = LINK_DEAD_DIRECT_REPROBE_DELAY_MS.saturating_add(jitter_ms);
        let retry_after_ms = now_ms.saturating_add(delay_ms);
        let peer_name = self.peer_display_name(&node_addr);
        let state = self
            .retry_pending
            .get_or_insert_with(node_addr, || RetryState::new(peer_config.clone()));
        state.peer_config = peer_config;
        state.reconnect = true;
        state.retry_count = 0;
        state.retry_after_ms = retry_after_ms;
        state.expires_at_ms = None;

        debug!(
            peer = %peer_name,
            delay_ms,
            jitter_ms,
            "Scheduling quick direct re-probe after link-dead removal"
        );
    }

    fn schedule_active_direct_refresh_no_transport_cooldown(
        &mut self,
        node_addr: NodeAddr,
        now_ms: u64,
    ) {
        let retry_after_ms = now_ms.saturating_add(ACTIVE_DIRECT_REFRESH_NO_TRANSPORT_COOLDOWN_MS);
        let peer_name = self.peer_display_name(&node_addr);
        let Some(state) = self.retry_pending.get_mut(&node_addr) else {
            return;
        };

        state.reconnect = true;
        state.retry_count = 0;
        state.retry_after_ms = retry_after_ms;
        state.expires_at_ms = None;

        debug!(
            peer = %peer_name,
            cooldown_ms = ACTIVE_DIRECT_REFRESH_NO_TRANSPORT_COOLDOWN_MS,
            "Pacing active direct refresh after no local transport candidate"
        );
    }

    async fn active_direct_refresh_has_concrete_candidate(&self, peer_config: &PeerConfig) -> bool {
        self.peer_address_candidates(peer_config)
            .await
            .into_iter()
            .any(|addr| !(addr.transport == "udp" && addr.addr.eq_ignore_ascii_case("nat")))
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
        let peer = self
            .config
            .auto_connect_peers()
            .filter_map(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .ok()
                    .map(|identity| (pc, identity))
            })
            .find(|(_, identity)| identity.node_addr() == node_addr)
            .map(|(pc, identity)| (pc.clone(), identity));
        let Some((peer_config, peer_identity)) = peer else {
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

        let decision = bootstrap.record_unstable_path_for_peer(peer_identity, now_ms);
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

        for node_addr in self.retry_pending.purge_expired(now_ms) {
            info!(
                peer = %self.peer_display_name(&node_addr),
                "Retry window expired, dropping pending retry state"
            );
        }
        if self.retry_pending.is_empty() {
            return;
        }

        // Collect retries that are due. Existing peers and live graph/FIPS
        // fallback sessions are direct-path refreshes; keep those in the
        // background so a synchronized link-dead event cannot start a
        // handshake/traversal storm that competes with fallback traffic
        // recovery.
        let due_tick = self.retry_pending.due_for_tick(
            now_ms,
            |node_addr| self.retry_is_background_direct_refresh(node_addr),
            MAX_RETRY_CONNECTIONS_PER_TICK,
            MAX_ACTIVE_DIRECT_REFRESH_RETRIES_PER_TICK,
        );
        if due_tick.has_deferred() {
            debug!(
                reconnect_due = due_tick.reconnect_total(),
                reconnect_processing = MAX_RETRY_CONNECTIONS_PER_TICK,
                reconnect_deferred = due_tick.reconnect_deferred(),
                active_due = due_tick.active_total(),
                active_processing = MAX_ACTIVE_DIRECT_REFRESH_RETRIES_PER_TICK,
                active_deferred = due_tick.active_deferred(),
                "Retry processing budget exhausted; deferring remaining peers"
            );
        }

        let due = due_tick.into_due_order().into_iter();

        for node_addr in due {
            if self.retry_is_background_direct_refresh(&node_addr) {
                let Some(peer_config) = self
                    .retry_pending
                    .get(&node_addr)
                    .map(|state| state.peer_config.clone())
                else {
                    continue;
                };

                if self.peers.contains_key(&node_addr)
                    && !self.active_peer_should_keep_direct_retry(&node_addr, &peer_config)
                {
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

                let has_concrete_direct_candidate = self
                    .active_direct_refresh_has_concrete_candidate(&peer_config)
                    .await;

                let refresh_result = if self.peers.contains_key(&node_addr) {
                    self.initiate_active_peer_direct_refresh_connection(&peer_config)
                        .await
                } else {
                    self.initiate_peer_retry_connection(&peer_config)
                        .await
                        .map(|_| true)
                };

                match refresh_result {
                    Ok(true) => {
                        if has_concrete_direct_candidate {
                            self.schedule_link_dead_reprobe(node_addr, now_ms);
                            debug!(
                                peer = %self.peer_display_name(&node_addr),
                                "Direct-path retry initiated while preserving active fallback peer"
                            );
                        } else {
                            self.schedule_active_direct_refresh_no_transport_cooldown(
                                node_addr, now_ms,
                            );
                            debug!(
                                peer = %self.peer_display_name(&node_addr),
                                "Queued traversal refresh while preserving active fallback peer"
                            );
                        }
                    }
                    Ok(false) => {
                        if self.active_peer_should_keep_direct_retry(&node_addr, &peer_config) {
                            self.schedule_active_direct_refresh_no_transport_cooldown(
                                node_addr, now_ms,
                            );
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
                        if (matches!(e, NodeError::NoTransportForType(_))
                            || e.is_local_route_unavailable())
                            && let Some(bootstrap) = self.nostr_discovery.clone()
                        {
                            bootstrap
                                .request_advert_stale_check(peer_config.npub.clone())
                                .await;
                        }
                        if e.is_local_route_unavailable() {
                            self.schedule_local_route_retry(node_addr, now_ms);
                        } else if matches!(e, NodeError::NoTransportForType(_)) {
                            self.schedule_active_direct_refresh_no_transport_cooldown(
                                node_addr, now_ms,
                            );
                        } else {
                            self.schedule_link_dead_reprobe(node_addr, now_ms);
                        }
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
    use std::collections::HashSet;

    const TEST_MAX_BACKOFF_MS: u64 = 300_000;

    fn test_addr(byte: u8) -> NodeAddr {
        NodeAddr::from_bytes([byte; 16])
    }

    fn test_retry_state(npub: &str, retry_after_ms: u64, expires_at_ms: Option<u64>) -> RetryState {
        RetryState {
            peer_config: PeerConfig::new(npub.to_string(), "udp", "127.0.0.1:9"),
            retry_count: 0,
            retry_after_ms,
            reconnect: true,
            expires_at_ms,
        }
    }

    #[test]
    fn quiet_traversal_refresh_jitter_spreads_across_heartbeat_window() {
        let samples = (0u8..=32)
            .map(|byte| quiet_traversal_refresh_jitter_ms(&test_addr(byte)))
            .collect::<Vec<_>>();

        assert!(
            samples.iter().all(|jitter| *jitter <= 10_000),
            "quiet traversal refresh jitter must stay within the heartbeat-sized spread window"
        );
        assert!(
            samples.iter().any(|jitter| *jitter > 1_000),
            "quiet traversal refreshes should not collapse roster probes into the old one-second window"
        );
    }

    #[test]
    fn pending_route_retries_own_expiry_due_order_and_budgets() {
        let expired = test_addr(1);
        let reconnect_early = test_addr(2);
        let reconnect_late = test_addr(3);
        let active_early = test_addr(4);
        let active_late = test_addr(5);
        let future = test_addr(6);

        let mut pending = PendingRouteRetries::default();
        pending.insert(expired, test_retry_state("expired", 0, Some(100)));
        pending.insert(reconnect_late, test_retry_state("reconnect-late", 80, None));
        pending.insert(
            reconnect_early,
            test_retry_state("reconnect-early", 20, None),
        );
        pending.insert(active_late, test_retry_state("active-late", 70, None));
        pending.insert(active_early, test_retry_state("active-early", 10, None));
        pending.insert(future, test_retry_state("future", 150, None));

        assert_eq!(pending.purge_expired(100), vec![expired]);
        assert!(!pending.contains_key(&expired));
        assert!(pending.contains_key(&future));

        let active_peers: HashSet<NodeAddr> = [active_early, active_late].into_iter().collect();
        let due = pending.due_for_tick(100, |addr| active_peers.contains(addr), 1, 1);

        assert_eq!(due.reconnect_total(), 2);
        assert_eq!(due.reconnect_deferred(), 1);
        assert_eq!(due.active_total(), 2);
        assert_eq!(due.active_deferred(), 1);
        assert_eq!(due.into_due_order(), vec![reconnect_early, active_early]);
    }

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
