//! MMP report dispatch, periodic report generation, and operator logging.
//!
//! Handles incoming SenderReport / ReceiverReport messages, drives
//! periodic report generation on the tick timer, and emits periodic
//! and teardown metric logs.

use crate::mmp::MmpMode;
use crate::mmp::MmpSessionState;
use crate::mmp::report::{ReceiverReport, SenderReport};
use crate::node::Node;
use crate::protocol::{
    LinkMessageType, PathMtuNotification, SessionMessageType, SessionReceiverReport,
    SessionSenderReport,
};
use crate::{NodeAddr, PeerIdentity};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Format bytes/sec as human-readable throughput.
fn format_throughput(bps: f64) -> String {
    if bps == 0.0 {
        "n/a".to_string()
    } else if bps >= 1_000_000.0 {
        format!("{:.1}MB/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1}KB/s", bps / 1_000.0)
    } else {
        format!("{:.0}B/s", bps)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct ProcessedMmpReceiverReport {
    first_rtt: bool,
    srtt_ms: Option<f64>,
    loss_rate: f64,
    etx: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MmpReceiverReportSkip {
    UnknownPeer,
    MmpDisabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MmpLinkReport {
    node_addr: NodeAddr,
    encoded: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct MmpLinkReportBatch {
    sender_reports: Vec<MmpLinkReport>,
    receiver_reports: Vec<MmpLinkReport>,
    metric_logs: Vec<MmpLinkMetricSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct MmpLinkMetricSnapshot {
    node_addr: NodeAddr,
    rtt_ms: Option<f64>,
    loss_rate: Option<f64>,
    jitter_ms: f64,
    goodput_bps: f64,
    tx_packets: u64,
    rx_packets: u64,
}

impl crate::node::PeerLifecycleRegistry {
    fn process_mmp_receiver_report(
        &mut self,
        from: &NodeAddr,
        rr: &ReceiverReport,
        now: Instant,
    ) -> Result<ProcessedMmpReceiverReport, MmpReceiverReportSkip> {
        let peer = self
            .active
            .get_mut(from)
            .ok_or(MmpReceiverReportSkip::UnknownPeer)?;

        let our_timestamp_ms = peer.session_elapsed_ms();
        let Some(mmp) = peer.mmp_mut() else {
            return Err(MmpReceiverReportSkip::MmpDisabled);
        };

        // Process the report: computes RTT from timestamp echo, updates
        // loss rate, goodput rate, jitter trend, and ETX.
        let first_rtt = mmp
            .metrics
            .process_receiver_report(rr, our_timestamp_ms, now);

        // Feed SRTT back to sender/receiver report interval tuning.
        if let Some(srtt_ms) = mmp.metrics.srtt_ms() {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_from_srtt(srtt_us);
            mmp.receiver.update_report_interval_from_srtt(srtt_us);
        }

        // Update reverse delivery ratio from our own receiver state
        // (what fraction of peer's frames we received), using per-interval
        // deltas.
        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);

        Ok(ProcessedMmpReceiverReport {
            first_rtt,
            srtt_ms: mmp.metrics.srtt_ms(),
            loss_rate: mmp.metrics.loss_rate(),
            etx: mmp.metrics.etx,
        })
    }

    fn collect_due_mmp_link_reports(&mut self, now: Instant) -> MmpLinkReportBatch {
        let mut batch = MmpLinkReportBatch::default();

        for (node_addr, peer) in self.active.iter_mut() {
            let Some(mmp) = peer.mmp_mut() else {
                continue;
            };

            let mode = mmp.mode();

            if mode == MmpMode::Full
                && mmp.sender.should_send_report(now)
                && let Some(sr) = mmp.sender.build_report(now)
            {
                batch.sender_reports.push(MmpLinkReport {
                    node_addr: *node_addr,
                    encoded: sr.encode(),
                });
            }

            if mode != MmpMode::Minimal
                && mmp.receiver.should_send_report(now)
                && let Some(rr) = mmp.receiver.build_report(now)
            {
                batch.receiver_reports.push(MmpLinkReport {
                    node_addr: *node_addr,
                    encoded: rr.encode(),
                });
            }

            if mmp.should_log(now) {
                let metrics = &mmp.metrics;
                batch.metric_logs.push(MmpLinkMetricSnapshot {
                    node_addr: *node_addr,
                    rtt_ms: metrics
                        .rtt_trend
                        .initialized()
                        .then(|| metrics.rtt_trend.long() / 1000.0),
                    loss_rate: metrics
                        .loss_trend
                        .initialized()
                        .then(|| metrics.loss_trend.long()),
                    jitter_ms: mmp.receiver.jitter_us() as f64 / 1000.0,
                    goodput_bps: metrics.goodput_bps(),
                    tx_packets: mmp.sender.cumulative_packets_sent(),
                    rx_packets: mmp.receiver.cumulative_packets_recv(),
                });
                mmp.mark_logged(now);
            }
        }

        batch
    }
}

impl Node {
    /// Handle an incoming SenderReport from a peer.
    ///
    /// The peer is telling us about what they sent. We feed this to our
    /// receiver state for cross-reference (not currently used for metrics,
    /// but stored for future use).
    pub(in crate::node) fn handle_sender_report(&mut self, from: &NodeAddr, payload: &[u8]) {
        let sr = match SenderReport::decode(payload) {
            Ok(sr) => sr,
            Err(e) => {
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed SenderReport");
                return;
            }
        };

        let peer = match self.peers.get_mut(from) {
            Some(p) => p,
            None => {
                debug!(from = %self.peer_display_name(from), "SenderReport from unknown peer");
                return;
            }
        };

        if peer.mmp().is_none() {
            return;
        }

        trace!(
            from = %self.peer_display_name(from),
            cum_pkts = sr.cumulative_packets_sent,
            interval_bytes = sr.interval_bytes_sent,
            "Received SenderReport"
        );

        // Store sender's report in receiver state for cross-reference.
        // Currently informational; the receiver already tracks its own
        // counters and echoes timestamps from data frames.
    }

    /// Handle an incoming ReceiverReport from a peer.
    ///
    /// The peer is telling us about what they received from us. We feed
    /// this to our metrics to compute RTT, loss rate, and trend indicators.
    pub(in crate::node) async fn handle_receiver_report(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
    ) {
        let rr = match ReceiverReport::decode(payload) {
            Ok(rr) => rr,
            Err(e) => {
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed ReceiverReport");
                return;
            }
        };

        let peer_name = self.peer_display_name(from);

        let processed = match self
            .peers
            .process_mmp_receiver_report(from, &rr, Instant::now())
        {
            Ok(processed) => processed,
            Err(MmpReceiverReportSkip::UnknownPeer) => {
                debug!(from = %peer_name, "ReceiverReport from unknown peer");
                return;
            }
            Err(MmpReceiverReportSkip::MmpDisabled) => return,
        };

        trace!(
            from = %peer_name,
            rtt_ms = ?processed.srtt_ms,
            loss = format_args!("{:.1}%", processed.loss_rate * 100.0),
            etx = format_args!("{:.2}", processed.etx),
            "Processed ReceiverReport"
        );

        // First RTT sample — peer is now eligible for parent selection.
        // Trigger re-evaluation so the node doesn't wait for the next
        // periodic tick or TreeAnnounce.
        if processed.first_rtt {
            let peer_costs: std::collections::HashMap<crate::NodeAddr, f64> = self
                .peers
                .iter()
                .filter(|(_, p)| p.can_send() && p.has_srtt())
                .map(|(a, p)| (*a, p.link_cost()))
                .collect();
            if let Some(new_parent) = self.tree_state.evaluate_parent(&peer_costs) {
                let new_seq = self.tree_state.my_declaration().sequence() + 1;
                let timestamp = crate::time::now_secs();
                let flap_dampened = self.tree_state.set_parent(new_parent, new_seq, timestamp);
                self.tree_state.recompute_coords();
                if let Err(e) = self.tree_state.sign_declaration(&self.identity) {
                    warn!(error = %e, "Failed to sign declaration after first-RTT parent eval");
                    return;
                }
                self.coord_cache.clear();
                self.reset_discovery_backoff();
                self.stats_mut().tree.parent_switched += 1;
                self.stats_mut().tree.parent_switches += 1;
                info!(
                    new_parent = %self.peer_display_name(&new_parent),
                    new_seq = new_seq,
                    new_root = %self.tree_state.root(),
                    depth = self.tree_state.my_coords().depth(),
                    trigger = "first-rtt",
                    "Parent switched after first RTT measurement"
                );
                if flap_dampened {
                    self.stats_mut().tree.flap_dampened += 1;
                    warn!("Flap dampening engaged: excessive parent switches detected");
                }
                self.send_tree_announce_to_all().await;
                let all_peers: Vec<crate::NodeAddr> = self.peers.keys().copied().collect();
                self.bloom_state.mark_all_updates_needed(all_peers);
            } else if !self.tree_state.is_root() && self.tree_state.should_be_root() {
                self.tree_state.become_root();
                if let Err(e) = self.tree_state.sign_declaration(&self.identity) {
                    warn!(error = %e, "Failed to sign self-root declaration after first-RTT");
                    return;
                }
                self.coord_cache.clear();
                self.reset_discovery_backoff();
                self.stats_mut().tree.parent_switched += 1;
                self.stats_mut().tree.parent_switches += 1;
                info!(
                    new_root = %self.tree_state.root(),
                    trigger = "first-rtt",
                    "Self-promoted to root after first RTT: smallest visible NodeAddr"
                );
                self.send_tree_announce_to_all().await;
                let all_peers: Vec<crate::NodeAddr> = self.peers.keys().copied().collect();
                self.bloom_state.mark_all_updates_needed(all_peers);
            }
        }
    }

    /// Check all peers for pending MMP reports and send them.
    ///
    /// Called from the tick handler. Also emits periodic operator logs.
    pub(in crate::node) async fn check_mmp_reports(&mut self) {
        let batch = self.peers.collect_due_mmp_link_reports(Instant::now());

        for metrics in &batch.metric_logs {
            let peer_name = self.peer_display_name(&metrics.node_addr);
            Self::log_mmp_metrics(&peer_name, metrics);
        }

        for report in batch.sender_reports {
            if let Err(e) = self
                .send_encrypted_link_message(&report.node_addr, &report.encoded)
                .await
            {
                debug!(peer = %self.peer_display_name(&report.node_addr), error = %e, "Failed to send SenderReport");
            }
        }

        for report in batch.receiver_reports {
            if let Err(e) = self
                .send_encrypted_link_message(&report.node_addr, &report.encoded)
                .await
            {
                debug!(peer = %self.peer_display_name(&report.node_addr), error = %e, "Failed to send ReceiverReport");
            }
        }
    }

    /// Emit periodic MMP metrics for a peer.
    fn log_mmp_metrics(peer_name: &str, metrics: &MmpLinkMetricSnapshot) {
        let rtt_str = metrics
            .rtt_ms
            .map(|rtt| format!("{rtt:.1}ms"))
            .unwrap_or_else(|| "n/a".to_string());
        let loss_str = metrics
            .loss_rate
            .map(|loss| format!("{:.1}%", loss * 100.0))
            .unwrap_or_else(|| "n/a".to_string());

        debug!(
            peer = %peer_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", metrics.jitter_ms),
            goodput = %format_throughput(metrics.goodput_bps),
            tx_pkts = metrics.tx_packets,
            rx_pkts = metrics.rx_packets,
            "MMP link metrics"
        );
    }

    /// Emit a teardown log summarizing lifetime MMP metrics for a removed peer.
    pub(in crate::node) fn log_mmp_teardown(peer_name: &str, mmp: &crate::mmp::MmpPeerState) {
        let m = &mmp.metrics;
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        let rtt_str = match m.srtt_ms() {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };
        let loss_str = format!("{:.1}%", m.loss_rate() * 100.0);

        debug!(
            peer = %peer_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            etx = format_args!("{:.2}", m.etx),
            goodput = %format_throughput(m.goodput_bps()),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            tx_bytes = mmp.sender.cumulative_bytes_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            rx_bytes = mmp.receiver.cumulative_bytes_recv(),
            "MMP link teardown"
        );
    }

    // === Session-layer MMP ===

    /// Check all sessions for pending MMP reports and send them.
    ///
    /// Called from the tick handler. Also emits periodic session MMP logs.
    /// Uses the collect-then-send pattern to avoid borrowing conflicts.
    pub(in crate::node) async fn check_session_mmp_reports(&mut self) {
        let now = Instant::now();

        // Collect reports to send: (dest_addr, msg_type, encoded_body)
        let mut reports: Vec<(NodeAddr, u8, Vec<u8>)> = Vec::new();

        for (dest_addr, entry) in self.sessions.iter_mut() {
            // Compute display name before taking mutable MMP borrow
            let session_name = self
                .peer_aliases
                .get(dest_addr)
                .cloned()
                .unwrap_or_else(|| {
                    let (xonly, _) = entry.remote_pubkey().x_only_public_key();
                    crate::PeerIdentity::from_pubkey(xonly).short_npub()
                });

            let Some(mmp) = entry.mmp_mut() else {
                continue;
            };

            let mode = mmp.mode();

            // Sender reports: Full mode only
            if mode == MmpMode::Full
                && mmp.sender.should_send_report(now)
                && let Some(sr) = mmp.sender.build_report(now)
            {
                let session_sr: SessionSenderReport = SessionSenderReport::from(&sr);
                reports.push((
                    *dest_addr,
                    SessionMessageType::SenderReport.to_byte(),
                    session_sr.encode(),
                ));
            }

            // Receiver reports: Full and Lightweight modes
            if mode != MmpMode::Minimal
                && mmp.receiver.should_send_report(now)
                && let Some(rr) = mmp.receiver.build_report(now)
            {
                let session_rr: SessionReceiverReport = SessionReceiverReport::from(&rr);
                reports.push((
                    *dest_addr,
                    SessionMessageType::ReceiverReport.to_byte(),
                    session_rr.encode(),
                ));
            }

            // PathMtu notifications (all modes)
            if mmp.path_mtu.should_send_notification(now)
                && let Some(mtu_value) = mmp.path_mtu.build_notification(now)
            {
                let notif = PathMtuNotification::new(mtu_value);
                reports.push((
                    *dest_addr,
                    SessionMessageType::PathMtuNotification.to_byte(),
                    notif.encode(),
                ));
            }

            // Periodic operator logging
            if mmp.should_log(now) {
                Self::log_session_mmp_metrics(&session_name, mmp);
                mmp.mark_logged(now);
            }
        }

        // Send collected reports via session-layer encryption.
        // Track per-destination success/failure for backoff and log suppression.
        let mut send_results: Vec<(NodeAddr, bool)> = Vec::new();
        for (dest_addr, msg_type, body) in reports {
            match self.send_session_msg(&dest_addr, msg_type, &body).await {
                Ok(()) => {
                    send_results.push((dest_addr, true));
                }
                Err(e) => {
                    // Peek at current failure count for log suppression
                    let failures = self
                        .sessions
                        .get(&dest_addr)
                        .and_then(|entry| entry.mmp())
                        .map(|mmp| mmp.sender.consecutive_send_failures())
                        .unwrap_or(0);

                    if failures < 3 {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            msg_type,
                            error = %e,
                            "Failed to send session MMP report"
                        );
                    } else if failures == 3 {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            "Suppressing further session MMP send failure logs"
                        );
                    }
                    // failures > 3: silently suppressed

                    send_results.push((dest_addr, false));
                }
            }
        }

        // Update backoff state from send results.
        // Deduplicate: a destination counts as success if ANY report succeeded,
        // failure only if ALL reports for that destination failed.
        let mut dest_success: std::collections::HashMap<NodeAddr, bool> =
            std::collections::HashMap::new();
        for (dest, ok) in &send_results {
            let entry = dest_success.entry(*dest).or_insert(false);
            if *ok {
                *entry = true;
            }
        }
        for (dest_addr, success) in dest_success {
            if let Some(entry) = self.sessions.get_mut(&dest_addr)
                && let Some(mmp) = entry.mmp_mut()
            {
                if success {
                    let prev = mmp.sender.record_send_success();
                    if prev > 3 {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            consecutive_failures = prev,
                            "Resumed session MMP reporting"
                        );
                    }
                } else {
                    mmp.sender.record_send_failure();
                }
            }
        }
    }

    /// Emit periodic session MMP metrics.
    fn log_session_mmp_metrics(session_name: &str, mmp: &MmpSessionState) {
        let m = &mmp.metrics;

        let rtt_str = if m.rtt_trend.initialized() {
            format!("{:.1}ms", m.rtt_trend.long() / 1000.0)
        } else {
            "n/a".to_string()
        };
        let loss_str = if m.loss_trend.initialized() {
            format!("{:.1}%", m.loss_trend.long() * 100.0)
        } else {
            "n/a".to_string()
        };
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        debug!(
            session = %session_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            goodput = %format_throughput(m.goodput_bps()),
            mtu = mmp.path_mtu.last_observed_mtu(),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            "MMP session metrics"
        );
    }

    /// Emit a teardown log summarizing lifetime session MMP metrics.
    pub(in crate::node) fn log_session_mmp_teardown(session_name: &str, mmp: &MmpSessionState) {
        let m = &mmp.metrics;
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        let rtt_str = match m.srtt_ms() {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };
        let loss_str = format!("{:.1}%", m.loss_rate() * 100.0);

        debug!(
            session = %session_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            etx = format_args!("{:.2}", m.etx),
            goodput = %format_throughput(m.goodput_bps()),
            send_mtu = mmp.path_mtu.current_mtu(),
            observed_mtu = mmp.path_mtu.last_observed_mtu(),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            tx_bytes = mmp.sender.cumulative_bytes_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            rx_bytes = mmp.receiver.cumulative_bytes_recv(),
            "MMP session teardown"
        );
    }

    pub(in crate::node) fn traversal_path_link_dead_timeout(
        &self,
        node_addr: &NodeAddr,
        dead_timeout: Duration,
        fast_dead_timeout: Duration,
    ) -> Option<Duration> {
        let peer_config = self.config.auto_connect_peers().find(|pc| {
            PeerIdentity::from_npub(&pc.npub)
                .map(|id| id.node_addr() == node_addr)
                .unwrap_or(false)
        })?;
        if !self.active_peer_uses_traversal_path(node_addr, peer_config) {
            return None;
        }

        let heartbeat = Duration::from_secs(self.config.node.heartbeat_interval_secs.max(1));
        let recent_path_timeout = heartbeat.saturating_mul(2) + Duration::from_secs(2);
        Some(recent_path_timeout.max(fast_dead_timeout).min(dead_timeout))
    }

    /// Send heartbeats and remove dead peers.
    ///
    /// Called from the tick handler. Sends a 1-byte heartbeat to each peer
    /// whose heartbeat interval has elapsed, and removes any peer that
    /// hasn't sent us a frame within the link dead timeout.
    ///
    /// While the kernel has recently told us a `transport.send` was
    /// locally unsendable (NetworkUnreachable / HostUnreachable /
    /// AddrNotAvailable), the dead-timeout collapses to
    /// `fast_link_dead_timeout_secs`. Steady-state behavior is unchanged
    /// because the signal is set on send-error and cleared on send-success.
    pub(in crate::node) async fn check_link_heartbeats(&mut self) {
        let now = Instant::now();
        let heartbeat_interval = Duration::from_secs(self.config.node.heartbeat_interval_secs);
        let dead_timeout = Duration::from_secs(self.config.node.link_dead_timeout_secs);
        let fast_dead_timeout = Duration::from_secs(self.config.node.fast_link_dead_timeout_secs);
        let max_rekey_resends = self.config.node.rate_limit.handshake_max_resends;
        self.purge_expired_local_send_failures(now);
        let defer_dead_peer_removal = self.rx_loop_maintenance_timed_out_recently();
        let heartbeat_msg = [LinkMessageType::Heartbeat.to_byte()];

        // Collect heartbeats to send and direct paths to demote.
        let mut heartbeats: Vec<NodeAddr> = Vec::new();
        let mut dead_peers: Vec<(NodeAddr, Duration)> = Vec::new();

        for (node_addr, peer) in self.peers.iter() {
            if !peer.can_send() {
                continue;
            }

            // Check liveness via MMP receiver last_recv_time.
            // Fall back to session_start for peers that never sent data.
            let local_send_failure_timeout = self.local_send_failure_dead_timeout_for_peer(
                node_addr,
                now,
                dead_timeout,
                fast_dead_timeout,
            );
            let effective_dead_timeout = self
                .traversal_path_link_dead_timeout(
                    node_addr,
                    local_send_failure_timeout,
                    fast_dead_timeout,
                )
                .unwrap_or(local_send_failure_timeout);
            let time_dead = if let Some(mmp) = peer.mmp() {
                let reference_time = mmp
                    .receiver
                    .last_recv_time()
                    .unwrap_or(peer.session_start());
                now.duration_since(reference_time) >= effective_dead_timeout
            } else {
                false
            };
            let rekey_active = peer.rekey_in_progress()
                && peer.rekey_msg1().is_some()
                && peer.rekey_msg1_resend_count() < max_rekey_resends;
            let is_dead = peer.is_healthy() && time_dead && !rekey_active;
            if is_dead {
                if defer_dead_peer_removal {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        timeout_secs = effective_dead_timeout.as_secs(),
                        "Deferring link-dead peer removal after recent rx-loop maintenance timeout"
                    );
                    heartbeats.push(*node_addr);
                } else {
                    dead_peers.push((*node_addr, effective_dead_timeout));
                }
                continue;
            }

            // Check if heartbeat is due
            let needs_heartbeat = match peer.last_heartbeat_sent() {
                None => true,
                Some(last) => now.duration_since(last) >= heartbeat_interval,
            };
            if needs_heartbeat {
                heartbeats.push(*node_addr);
            }
        }

        // Demote dead direct paths and schedule direct re-probe.
        let now_ms = Self::now_ms();

        for (addr, effective_dead_timeout) in &dead_peers {
            warn!(
                peer = %self.peer_display_name(addr),
                timeout_secs = effective_dead_timeout.as_secs(),
                fast = *effective_dead_timeout < dead_timeout,
                "Marking direct path stale after link-dead timeout"
            );
            self.record_link_dead_path_failure(addr, now_ms).await;
            self.remove_link_dead_peer(addr);
            self.schedule_link_dead_reprobe(*addr, now_ms);
            self.maybe_initiate_link_dead_fallback_lookup(addr).await;
        }

        // Send heartbeats (skip peers we just removed)
        for addr in heartbeats {
            if dead_peers.iter().any(|(dead_addr, _)| dead_addr == &addr) {
                continue;
            }
            match self
                .send_encrypted_link_message(&addr, &heartbeat_msg)
                .await
            {
                Ok(()) => {
                    if let Some(peer) = self.peers.get_mut(&addr) {
                        peer.mark_heartbeat_sent(now);
                    }
                }
                Err(e) => {
                    debug!(peer = %self.peer_display_name(&addr), error = %e, "Failed to send heartbeat");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::PeerLifecycleRegistry;
    use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseSession};
    use crate::peer::ActivePeer;
    use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
    use crate::utils::index::SessionIndex;
    use crate::{Identity, NodeAddr, PeerIdentity};
    use std::time::{Duration, Instant};

    fn node_addr(byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        NodeAddr::from_bytes(bytes)
    }

    fn make_fmp_session_pair(
        initiator: &Identity,
        responder: &Identity,
    ) -> (NoiseSession, NoiseSession) {
        let mut initiator_hs =
            NoiseHandshakeState::new_initiator(initiator.keypair(), responder.pubkey_full());
        let mut responder_hs = NoiseHandshakeState::new_responder(responder.keypair());
        initiator_hs.set_local_epoch([1u8; 8]);
        responder_hs.set_local_epoch([2u8; 8]);

        let msg1 = initiator_hs.write_message_1().unwrap();
        responder_hs.read_message_1(&msg1).unwrap();
        let msg2 = responder_hs.write_message_2().unwrap();
        initiator_hs.read_message_2(&msg2).unwrap();

        (
            initiator_hs.into_session().unwrap(),
            responder_hs.into_session().unwrap(),
        )
    }

    fn active_fmp_peer(local: &Identity, peer: &Identity, tag: u32) -> ActivePeer {
        active_fmp_peer_with_mmp_config(local, peer, tag, &crate::mmp::MmpConfig::default())
    }

    fn active_fmp_peer_with_mmp_config(
        local: &Identity,
        peer: &Identity,
        tag: u32,
        mmp_config: &crate::mmp::MmpConfig,
    ) -> ActivePeer {
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let (session, _) = make_fmp_session_pair(local, peer);
        ActivePeer::with_session(
            peer_identity,
            LinkId::new(tag.into()),
            1_000,
            session,
            SessionIndex::new(tag * 10 + 1),
            SessionIndex::new(tag * 10 + 2),
            TransportId::new(tag),
            TransportAddr::from_string(&format!("127.0.0.1:{}", 4_000 + tag)),
            LinkStats::new(),
            true,
            mmp_config,
            Some([2u8; 8]),
        )
    }

    fn sample_receiver_report(timestamp_echo: u32) -> ReceiverReport {
        ReceiverReport {
            highest_counter: 10,
            cumulative_packets_recv: 10,
            cumulative_bytes_recv: 1_200,
            timestamp_echo,
            dwell_time: 0,
            max_burst_loss: 0,
            mean_burst_loss: 0,
            jitter: 123,
            ecn_ce_count: 0,
            owd_trend: 0,
            burst_loss_count: 0,
            cumulative_reorder_count: 0,
            interval_packets_recv: 10,
            interval_bytes_recv: 1_200,
        }
    }

    #[test]
    fn peer_lifecycle_registry_owns_mmp_receiver_report_processing() {
        let local = Identity::generate();
        let peer_id = Identity::generate();
        let mut peer = active_fmp_peer(&local, &peer_id, 1);

        {
            let mmp = peer.mmp_mut().expect("MMP enabled");
            mmp.receiver
                .record_recv(10, 1, 1_200, false, Instant::now());
        }

        let mut peers = PeerLifecycleRegistry::default();
        peers.insert(*peer_id.node_addr(), peer);

        std::thread::sleep(Duration::from_millis(20));
        let outcome = peers
            .process_mmp_receiver_report(
                peer_id.node_addr(),
                &sample_receiver_report(1),
                Instant::now(),
            )
            .expect("receiver report should process");

        assert!(outcome.first_rtt);
        assert!(outcome.srtt_ms.is_some());
        assert_eq!(outcome.loss_rate, 0.0);
        assert_eq!(outcome.etx, 1.0);

        let peer = peers.get(peer_id.node_addr()).expect("peer retained");
        let mmp = peer.mmp().expect("MMP retained");
        assert_eq!(mmp.metrics.srtt_ms(), outcome.srtt_ms);
        assert!(peer.has_srtt());
        assert_eq!(mmp.receiver.cumulative_packets_recv(), 1);
        assert_eq!(mmp.receiver.highest_counter(), 10);
    }

    #[test]
    fn peer_lifecycle_registry_owns_mmp_receiver_report_skip_paths() {
        let mut peers = PeerLifecycleRegistry::default();
        let rr = sample_receiver_report(0);

        assert_eq!(
            peers.process_mmp_receiver_report(&node_addr(0x77), &rr, Instant::now()),
            Err(MmpReceiverReportSkip::UnknownPeer)
        );

        let no_mmp_identity = Identity::generate();
        let no_mmp_peer = ActivePeer::new(
            PeerIdentity::from_pubkey_full(no_mmp_identity.pubkey_full()),
            LinkId::new(9),
            1_000,
        );
        peers.insert(*no_mmp_identity.node_addr(), no_mmp_peer);

        assert_eq!(
            peers.process_mmp_receiver_report(no_mmp_identity.node_addr(), &rr, Instant::now()),
            Err(MmpReceiverReportSkip::MmpDisabled)
        );
    }

    #[test]
    fn peer_lifecycle_registry_owns_due_mmp_link_report_collection() {
        let local = Identity::generate();
        let peer_id = Identity::generate();
        let mut peer = active_fmp_peer(&local, &peer_id, 2);
        let now = Instant::now();

        {
            let mmp = peer.mmp_mut().expect("MMP enabled");
            mmp.sender.record_sent(12, 3, 512);
            mmp.receiver.record_recv(12, 3, 512, false, now);
        }

        let mut peers = PeerLifecycleRegistry::default();
        peers.insert(*peer_id.node_addr(), peer);

        let batch = peers.collect_due_mmp_link_reports(now + Duration::from_millis(1));
        assert_eq!(batch.sender_reports.len(), 1);
        assert_eq!(batch.receiver_reports.len(), 1);
        assert_eq!(batch.metric_logs.len(), 1);
        assert_eq!(batch.sender_reports[0].node_addr, *peer_id.node_addr());
        assert_eq!(batch.sender_reports[0].encoded[0], 0x01);
        assert_eq!(batch.receiver_reports[0].node_addr, *peer_id.node_addr());
        assert_eq!(batch.receiver_reports[0].encoded[0], 0x02);
        assert_eq!(batch.metric_logs[0].node_addr, *peer_id.node_addr());
        assert_eq!(batch.metric_logs[0].tx_packets, 1);
        assert_eq!(batch.metric_logs[0].rx_packets, 1);

        let second = peers.collect_due_mmp_link_reports(now + Duration::from_millis(2));
        assert!(second.sender_reports.is_empty());
        assert!(second.receiver_reports.is_empty());
        assert!(second.metric_logs.is_empty());
    }

    #[test]
    fn peer_lifecycle_registry_mmp_link_report_collection_respects_modes() {
        let local = Identity::generate();
        let lightweight_peer = Identity::generate();
        let minimal_peer = Identity::generate();
        let no_mmp_peer = Identity::generate();
        let now = Instant::now();

        let mut lightweight_config = crate::mmp::MmpConfig::default();
        lightweight_config.mode = MmpMode::Lightweight;
        let mut lightweight =
            active_fmp_peer_with_mmp_config(&local, &lightweight_peer, 3, &lightweight_config);
        {
            let mmp = lightweight.mmp_mut().expect("MMP enabled");
            mmp.sender.record_sent(1, 1, 100);
            mmp.receiver.record_recv(1, 1, 100, false, now);
        }

        let mut minimal_config = crate::mmp::MmpConfig::default();
        minimal_config.mode = MmpMode::Minimal;
        let mut minimal =
            active_fmp_peer_with_mmp_config(&local, &minimal_peer, 4, &minimal_config);
        {
            let mmp = minimal.mmp_mut().expect("MMP enabled");
            mmp.sender.record_sent(1, 1, 100);
            mmp.receiver.record_recv(1, 1, 100, false, now);
        }

        let no_mmp = ActivePeer::new(
            PeerIdentity::from_pubkey_full(no_mmp_peer.pubkey_full()),
            LinkId::new(5),
            1_000,
        );

        let mut peers = PeerLifecycleRegistry::default();
        peers.insert(*lightweight_peer.node_addr(), lightweight);
        peers.insert(*minimal_peer.node_addr(), minimal);
        peers.insert(*no_mmp_peer.node_addr(), no_mmp);

        let batch = peers.collect_due_mmp_link_reports(now + Duration::from_millis(1));

        assert!(batch.sender_reports.is_empty());
        assert_eq!(batch.receiver_reports.len(), 1);
        assert_eq!(
            batch.receiver_reports[0].node_addr,
            *lightweight_peer.node_addr()
        );
        assert_eq!(batch.receiver_reports[0].encoded[0], 0x02);
        assert_eq!(batch.metric_logs.len(), 2);
        assert!(
            batch
                .metric_logs
                .iter()
                .any(|metrics| metrics.node_addr == *lightweight_peer.node_addr())
        );
        assert!(
            batch
                .metric_logs
                .iter()
                .any(|metrics| metrics.node_addr == *minimal_peer.node_addr())
        );
    }
}
