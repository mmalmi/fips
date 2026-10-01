//! Bloom filter announce send/receive logic.
//!
//! Handles building, sending, and receiving FilterAnnounce messages,
//! including debounced propagation to peers.

use crate::NodeAddr;
use crate::bloom::BloomFilter;
use crate::protocol::FilterAnnounce;

use super::{Node, NodeError};
use std::collections::HashMap;
use tracing::{debug, warn};

impl Node {
    /// Collect inbound filters from all peers for outgoing filter computation.
    ///
    /// Returns a map of (peer_node_addr -> filter) for peers that
    /// have sent us a FilterAnnounce.
    pub(super) fn peer_inbound_filters(&self) -> HashMap<NodeAddr, BloomFilter> {
        let mut filters = HashMap::new();
        for (addr, peer) in &self.peers {
            if self.is_tree_peer(addr)
                && let Some(filter) = peer.inbound_filter()
            {
                filters.insert(*addr, filter.clone());
            }
        }
        filters
    }

    /// Build a FilterAnnounce for a specific peer.
    ///
    /// The outgoing filter excludes the destination peer's own filter
    /// to prevent routing loops (don't tell a peer about destinations
    /// reachable only through them).
    pub(super) fn build_filter_announce(&mut self, exclude_peer: &NodeAddr) -> FilterAnnounce {
        let peer_filters = self.peer_inbound_filters();
        let filter = self
            .bloom_state
            .compute_outgoing_filter(exclude_peer, &peer_filters);
        let sequence = self.bloom_state.next_sequence();
        FilterAnnounce::new(filter, sequence)
    }

    /// Send a FilterAnnounce to a specific peer, respecting debounce.
    ///
    /// If the peer is rate-limited, the update stays pending for
    /// delivery when its debounce deadline expires.
    pub(super) async fn send_filter_announce_to_peer(
        &mut self,
        peer_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();
        #[cfg(test)]
        let trace_due_before = self.bloom_state.pending_peer_deadline_ms(peer_addr);

        // Check debounce
        if !self.bloom_state.should_send_update(peer_addr, now_ms) {
            self.stats_mut().bloom.debounce_suppressed += 1;
            // Pending work remains scheduled for its debounce deadline.
            return Ok(());
        }

        // Reserve only the added fast retry before any send await. Failure or
        // cancellation retains the update and successful-send history; ordinary
        // periodic maintenance can still retry on its independently due tick.
        self.bloom_state
            .defer_update_retry(peer_addr, self.filter_announce_retry_at_ms());

        // Build and encode
        let announce = self.build_filter_announce(peer_addr);
        let sent_filter = announce.filter.clone();
        let encoded = announce.encode().map_err(|e| NodeError::SendFailed {
            node_addr: *peer_addr,
            reason: format!("FilterAnnounce encode failed: {}", e),
        })?;

        // Send
        if let Err(e) = self
            .send_dataplane_fmp_link_plaintext(peer_addr, &encoded, false)
            .await
        {
            self.bloom_state
                .defer_update_retry(peer_addr, self.filter_announce_retry_at_ms());
            self.stats_mut().bloom.send_failed += 1;
            return Err(e);
        }

        self.stats_mut().bloom.sent += 1;

        // Self-plausibility check: WARN if our own outgoing filter is
        // above the antipoison cap. Independent detection signal if
        // aggregation drift or an ingress-check bypass pushes us over
        // despite M1. Rate-limited to once per 60s globally — outgoing
        // cadence can be per-tick during churn, and we want the
        // operator to see one clear message, not spam.
        let max_fpr = self.config.node.bloom.max_inbound_fpr;
        let out_fill = sent_filter.fill_ratio();
        let out_fpr = out_fill.powi(sent_filter.hash_count() as i32);
        if out_fpr > max_fpr {
            let now = std::time::Instant::now();
            let should_warn = self
                .last_self_warn
                .map(|t| now.duration_since(t) >= std::time::Duration::from_secs(60))
                .unwrap_or(true);
            if should_warn {
                self.last_self_warn = Some(now);
                warn!(
                    to = %self.peer_display_name(peer_addr),
                    fill = format_args!("{:.3}", out_fill),
                    fpr = format_args!("{:.4}", out_fpr),
                    cap = format_args!("{:.4}", max_fpr),
                    "Outgoing filter above FPR cap — aggregation drift or missed ingress?"
                );
            }
        }

        // Record send and store the filter for change detection
        debug!(
            node = %self.node_addr(),
            peer = %self.peer_display_name(peer_addr),
            seq = announce.sequence,
            est_entries = match sent_filter.estimated_count(max_fpr) {
                Some(n) => format!("{:.0}", n),
                None => "—".to_string(),
            },
            set_bits = sent_filter.count_ones(),
            fill = format_args!("{:.1}%", sent_filter.fill_ratio() * 100.0),
            tree_peer = self.is_tree_peer(peer_addr),
            "Sent FilterAnnounce"
        );
        // Completion is a conservative debounce anchor even when a transport
        // accepts its write late. An incomplete send never advances history.
        self.bloom_state
            .record_update_sent(*peer_addr, Self::now_ms());
        self.bloom_state.record_sent_filter(*peer_addr, sent_filter);
        #[cfg(test)]
        self.bloom_state
            .trace_filter_send(peer_addr, announce.sequence, trace_due_before);
        if let Some(peer) = self.peers.get_mut(peer_addr) {
            peer.clear_filter_update_needed();
        }

        Ok(())
    }

    /// Send pending rate-limited filter announces whose debounce has expired.
    pub(super) async fn send_pending_filter_announces(&mut self) {
        let now_ms = Self::now_ms();

        let ready: Vec<NodeAddr> = self
            .peers
            .keys()
            .filter(|addr| self.bloom_state.should_send_update(addr, now_ms))
            .copied()
            .collect();

        self.send_filter_announces_to_peers(ready).await;
    }

    /// Dispatch only changed updates whose debounce and failed-send floor are
    /// due. Periodic refresh remains owned by the ordinary maintenance tick.
    pub(super) async fn send_due_filter_announces(&mut self) {
        let ready = self.bloom_state.pending_peers_due(Self::now_ms());
        self.send_filter_announces_to_peers(ready).await;
    }

    pub(super) fn pending_routing_announce_deadline_ms(&self) -> Option<u64> {
        self.pending_tree_announce_deadline_ms()
            .into_iter()
            .chain(self.bloom_state.pending_update_deadline_ms())
            .min()
    }

    pub(super) fn defer_filter_announce_retry(&mut self) {
        let retry_at = self.filter_announce_retry_at_ms();
        self.bloom_state.defer_pending_retries(retry_at);
    }

    fn filter_announce_retry_at_ms(&self) -> u64 {
        Self::now_ms().saturating_add(
            self.config
                .node
                .tick_interval_secs
                .saturating_mul(1_000)
                .max(1),
        )
    }

    async fn send_filter_announces_to_peers(&mut self, ready: Vec<NodeAddr>) {
        for peer_addr in ready {
            if !self.peers.contains_key(&peer_addr) {
                self.bloom_state.remove_peer_state(&peer_addr);
                continue;
            }
            if let Err(e) = self.send_filter_announce_to_peer(&peer_addr).await {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to send pending FilterAnnounce"
                );
            }
        }
    }

    /// Handle an inbound FilterAnnounce from an authenticated peer.
    ///
    /// 1. Decode and validate the message
    /// 2. Check sequence freshness (reject stale/replay)
    /// 3. Store the filter on the peer
    /// 4. Mark other peers for outgoing filter update
    pub(super) async fn handle_filter_announce(&mut self, from: &NodeAddr, payload: &[u8]) {
        self.stats_mut().bloom.received += 1;

        let announce = match FilterAnnounce::decode(payload) {
            Ok(a) => a,
            Err(e) => {
                self.stats_mut().bloom.decode_error += 1;
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed FilterAnnounce");
                return;
            }
        };

        // Validate
        if !announce.is_valid() {
            self.stats_mut().bloom.invalid += 1;
            debug!(from = %self.peer_display_name(from), "FilterAnnounce filter/size_class mismatch");
            return;
        }
        if !announce.is_v1_compliant() {
            self.stats_mut().bloom.non_v1 += 1;
            debug!(from = %self.peer_display_name(from), size_class = announce.size_class, "Non-v1 FilterAnnounce rejected");
            return;
        }

        // Check peer exists
        let current_seq = match self.peers.get(from) {
            Some(peer) => peer.filter_sequence(),
            None => {
                self.stats_mut().bloom.unknown_peer += 1;
                debug!(from = %self.peer_display_name(from), "FilterAnnounce from unknown peer");
                return;
            }
        };

        // Reject stale/replay
        if announce.sequence <= current_seq {
            self.stats_mut().bloom.stale += 1;
            debug!(
                from = %self.peer_display_name(from),
                received_seq = announce.sequence,
                current_seq = current_seq,
                "Stale FilterAnnounce rejected"
            );
            return;
        }

        // Antipoison FPR cap. Reject announces whose FPR exceeds
        // node.bloom.max_inbound_fpr. Silent on the wire (no NACK) —
        // the peer's prior accepted filter and filter_sequence stay
        // untouched so the peer is not permanently silenced and an
        // on-path attacker cannot weaponize a single corrupted frame
        // to wipe a victim's contribution to aggregation.
        let max_fpr = self.config.node.bloom.max_inbound_fpr;
        let fill = announce.filter.fill_ratio();
        let fpr = fill.powi(announce.filter.hash_count() as i32);
        if fpr > max_fpr {
            self.stats_mut().bloom.fill_exceeded += 1;
            debug!(
                from = %self.peer_display_name(from),
                seq = announce.sequence,
                fill = format_args!("{:.3}", fill),
                fpr = format_args!("{:.4}", fpr),
                cap = format_args!("{:.4}", max_fpr),
                "FilterAnnounce above FPR cap rejected"
            );
            return;
        }

        self.stats_mut().bloom.accepted += 1;

        let now_ms = Self::now_ms();

        debug!(
            node = %self.node_addr(),
            from = %self.peer_display_name(from),
            seq = announce.sequence,
            est_entries = match announce.filter.estimated_count(max_fpr) {
                Some(n) => format!("{:.0}", n),
                None => "—".to_string(),
            },
            set_bits = announce.filter.count_ones(),
            fill = format_args!("{:.1}%", announce.filter.fill_ratio() * 100.0),
            tree_peer = self.is_tree_peer(from),
            "Received FilterAnnounce"
        );

        // Store on peer
        if let Some(peer) = self.peers.get_mut(from) {
            peer.update_filter(announce.filter, announce.sequence, now_ms);
        }
        #[cfg(test)]
        self.bloom_state.trace_filter_received(
            from,
            announce.sequence,
            self.is_tree_peer(from),
            self.peers.get(from).and_then(|peer| peer.inbound_filter()),
        );

        // Check which peers' outgoing filters actually changed.
        // All peers receive filters, but only tree peers' inbound filters
        // are merged into outgoing computation (tree-only propagation).
        let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();
        let peer_filters = self.peer_inbound_filters();
        self.bloom_state
            .mark_changed_peers(from, &peer_addrs, &peer_filters);
        self.resume_unsent_lookup_via_peer(from).await;
    }

    /// Check bloom filter state on tick (called from event loop).
    ///
    /// Refresh unchanged filters to repair loss, then send pending debounced
    /// announcements. Refresh shares the successful-send history and rate limit.
    pub(super) async fn check_bloom_state(&mut self) {
        let now_ms = Self::now_ms();
        let refresh_ms = self
            .config
            .node
            .bloom
            .announce_refresh_interval_secs
            .saturating_mul(1000);
        for peer in self.peers.keys() {
            if self.bloom_state.refresh_due(peer, now_ms, refresh_ms) {
                // Mark before any send await so failure/cancellation retains the
                // update. Only a successful send advances its refresh history.
                self.bloom_state.mark_update_needed(*peer);
            }
        }
        self.send_pending_filter_announces().await;
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod deadlines;
