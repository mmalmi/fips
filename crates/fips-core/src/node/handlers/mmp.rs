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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionMmpReport {
    dest_addr: NodeAddr,
    msg_type: u8,
    encoded: Vec<u8>,
    prior_failures: u32,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct SessionMmpReportBatch {
    reports: Vec<SessionMmpReport>,
    metric_logs: Vec<SessionMmpMetricSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
struct SessionMmpMetricSnapshot {
    dest_addr: NodeAddr,
    fallback_session_name: String,
    rtt_ms: Option<f64>,
    loss_rate: Option<f64>,
    jitter_ms: f64,
    goodput_bps: f64,
    send_mtu: u16,
    observed_mtu: u16,
    tx_packets: u64,
    rx_packets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionMmpSendResult {
    dest_addr: NodeAddr,
    success: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionMmpReportingResumed {
    dest_addr: NodeAddr,
    consecutive_failures: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct LinkHeartbeatPlan {
    heartbeats: Vec<NodeAddr>,
    dead_peers: Vec<LinkDeadPeerPlan>,
    deferred_dead_peers: Vec<LinkDeadPeerPlan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkDeadPeerPlan {
    node_addr: NodeAddr,
    effective_dead_timeout: Duration,
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

    fn plan_link_heartbeat_tick<F>(
        &self,
        now: Instant,
        heartbeat_interval: Duration,
        max_rekey_resends: u32,
        defer_dead_peer_removal: bool,
        mut effective_dead_timeout_for: F,
    ) -> LinkHeartbeatPlan
    where
        F: FnMut(&NodeAddr) -> Duration,
    {
        let mut plan = LinkHeartbeatPlan::default();

        for (node_addr, peer) in self.iter() {
            if !peer.can_send() {
                continue;
            }

            let effective_dead_timeout = effective_dead_timeout_for(node_addr);
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
                let dead_peer = LinkDeadPeerPlan {
                    node_addr: *node_addr,
                    effective_dead_timeout,
                };
                if defer_dead_peer_removal {
                    plan.deferred_dead_peers.push(dead_peer);
                    plan.heartbeats.push(*node_addr);
                } else {
                    plan.dead_peers.push(dead_peer);
                }
                continue;
            }

            let needs_heartbeat = match peer.last_heartbeat_sent() {
                None => true,
                Some(last) => now.duration_since(last) >= heartbeat_interval,
            };
            if needs_heartbeat {
                plan.heartbeats.push(*node_addr);
            }
        }

        plan
    }

    fn record_link_heartbeat_sent(&mut self, node_addr: &NodeAddr, now: Instant) -> bool {
        let Some(peer) = self.get_mut(node_addr) else {
            return false;
        };
        peer.mark_heartbeat_sent(now);
        true
    }
}

impl crate::node::SessionRegistry {
    fn collect_due_session_mmp_reports(&mut self, now: Instant) -> SessionMmpReportBatch {
        let mut batch = SessionMmpReportBatch::default();

        for (dest_addr, entry) in self.iter_mut() {
            let (xonly, _) = entry.remote_pubkey().x_only_public_key();
            let fallback_session_name = PeerIdentity::from_pubkey(xonly).short_npub();

            let Some(mmp) = entry.mmp_mut() else {
                continue;
            };

            let mode = mmp.mode();
            let prior_failures = mmp.sender.consecutive_send_failures();

            if mode == MmpMode::Full
                && mmp.sender.should_send_report(now)
                && let Some(sr) = mmp.sender.build_report(now)
            {
                let session_sr: SessionSenderReport = SessionSenderReport::from(&sr);
                batch.reports.push(SessionMmpReport {
                    dest_addr: *dest_addr,
                    msg_type: SessionMessageType::SenderReport.to_byte(),
                    encoded: session_sr.encode(),
                    prior_failures,
                });
            }

            if mode != MmpMode::Minimal
                && mmp.receiver.should_send_report(now)
                && let Some(rr) = mmp.receiver.build_report(now)
            {
                let session_rr: SessionReceiverReport = SessionReceiverReport::from(&rr);
                batch.reports.push(SessionMmpReport {
                    dest_addr: *dest_addr,
                    msg_type: SessionMessageType::ReceiverReport.to_byte(),
                    encoded: session_rr.encode(),
                    prior_failures,
                });
            }

            if mmp.path_mtu.should_send_notification(now)
                && let Some(mtu_value) = mmp.path_mtu.build_notification(now)
            {
                let notif = PathMtuNotification::new(mtu_value);
                batch.reports.push(SessionMmpReport {
                    dest_addr: *dest_addr,
                    msg_type: SessionMessageType::PathMtuNotification.to_byte(),
                    encoded: notif.encode(),
                    prior_failures,
                });
            }

            if mmp.should_log(now) {
                let metrics = &mmp.metrics;
                batch.metric_logs.push(SessionMmpMetricSnapshot {
                    dest_addr: *dest_addr,
                    fallback_session_name,
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
                    send_mtu: mmp.path_mtu.current_mtu(),
                    observed_mtu: mmp.path_mtu.last_observed_mtu(),
                    tx_packets: mmp.sender.cumulative_packets_sent(),
                    rx_packets: mmp.receiver.cumulative_packets_recv(),
                });
                mmp.mark_logged(now);
            }
        }

        batch
    }

    fn record_session_mmp_send_results(
        &mut self,
        send_results: impl IntoIterator<Item = SessionMmpSendResult>,
    ) -> Vec<SessionMmpReportingResumed> {
        let mut dest_success: std::collections::HashMap<NodeAddr, bool> =
            std::collections::HashMap::new();
        for result in send_results {
            let entry = dest_success.entry(result.dest_addr).or_insert(false);
            if result.success {
                *entry = true;
            }
        }

        let mut resumed = Vec::new();
        for (dest_addr, success) in dest_success {
            if let Some(entry) = self.get_mut(&dest_addr)
                && let Some(mmp) = entry.mmp_mut()
            {
                if success {
                    let prev = mmp.sender.record_send_success();
                    if prev > 3 {
                        resumed.push(SessionMmpReportingResumed {
                            dest_addr,
                            consecutive_failures: prev,
                        });
                    }
                } else {
                    mmp.sender.record_send_failure();
                }
            }
        }

        resumed
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
        let batch = self.sessions.collect_due_session_mmp_reports(now);

        for metrics in &batch.metric_logs {
            let session_name = self
                .peer_aliases
                .get(&metrics.dest_addr)
                .cloned()
                .unwrap_or_else(|| metrics.fallback_session_name.clone());
            Self::log_session_mmp_metrics(&session_name, metrics);
        }

        // Send collected reports via session-layer encryption.
        // Track per-destination success/failure for backoff and log suppression.
        let mut send_results = Vec::new();
        for report in batch.reports {
            match self
                .send_session_msg(&report.dest_addr, report.msg_type, &report.encoded)
                .await
            {
                Ok(()) => {
                    send_results.push(SessionMmpSendResult {
                        dest_addr: report.dest_addr,
                        success: true,
                    });
                }
                Err(e) => {
                    if report.prior_failures < 3 {
                        debug!(
                            dest = %self.peer_display_name(&report.dest_addr),
                            msg_type = report.msg_type,
                            error = %e,
                            "Failed to send session MMP report"
                        );
                    } else if report.prior_failures == 3 {
                        debug!(
                            dest = %self.peer_display_name(&report.dest_addr),
                            "Suppressing further session MMP send failure logs"
                        );
                    }
                    // failures > 3: silently suppressed

                    send_results.push(SessionMmpSendResult {
                        dest_addr: report.dest_addr,
                        success: false,
                    });
                }
            }
        }

        for resumed in self.sessions.record_session_mmp_send_results(send_results) {
            debug!(
                dest = %self.peer_display_name(&resumed.dest_addr),
                consecutive_failures = resumed.consecutive_failures,
                "Resumed session MMP reporting"
            );
        }
    }

    /// Emit periodic session MMP metrics.
    fn log_session_mmp_metrics(session_name: &str, metrics: &SessionMmpMetricSnapshot) {
        let rtt_str = metrics
            .rtt_ms
            .map(|rtt| format!("{rtt:.1}ms"))
            .unwrap_or_else(|| "n/a".to_string());
        let loss_str = metrics
            .loss_rate
            .map(|loss| format!("{:.1}%", loss * 100.0))
            .unwrap_or_else(|| "n/a".to_string());

        debug!(
            session = %session_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", metrics.jitter_ms),
            goodput = %format_throughput(metrics.goodput_bps),
            mtu = metrics.observed_mtu,
            send_mtu = metrics.send_mtu,
            tx_pkts = metrics.tx_packets,
            rx_pkts = metrics.rx_packets,
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

        let effective_dead_timeouts: std::collections::HashMap<NodeAddr, Duration> = self
            .peers
            .iter()
            .map(|(node_addr, _)| {
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
                (*node_addr, effective_dead_timeout)
            })
            .collect();
        let heartbeat_plan = self.peers.plan_link_heartbeat_tick(
            now,
            heartbeat_interval,
            max_rekey_resends,
            defer_dead_peer_removal,
            |node_addr| {
                effective_dead_timeouts
                    .get(node_addr)
                    .copied()
                    .unwrap_or(dead_timeout)
            },
        );

        for dead_peer in &heartbeat_plan.deferred_dead_peers {
            debug!(
                peer = %self.peer_display_name(&dead_peer.node_addr),
                timeout_secs = dead_peer.effective_dead_timeout.as_secs(),
                "Deferring link-dead peer removal after recent rx-loop maintenance timeout"
            );
        }

        // Demote dead direct paths and schedule direct re-probe.
        let now_ms = Self::now_ms();

        for dead_peer in &heartbeat_plan.dead_peers {
            warn!(
                peer = %self.peer_display_name(&dead_peer.node_addr),
                timeout_secs = dead_peer.effective_dead_timeout.as_secs(),
                fast = dead_peer.effective_dead_timeout < dead_timeout,
                "Marking direct path stale after link-dead timeout"
            );
            self.record_link_dead_path_failure(&dead_peer.node_addr, now_ms)
                .await;
            self.remove_link_dead_peer(&dead_peer.node_addr);
            self.schedule_link_dead_reprobe(dead_peer.node_addr, now_ms);
            self.maybe_initiate_link_dead_fallback_lookup(&dead_peer.node_addr)
                .await;
        }

        // Send heartbeats (skip peers we just removed)
        for addr in heartbeat_plan.heartbeats {
            if heartbeat_plan
                .dead_peers
                .iter()
                .any(|dead_peer| dead_peer.node_addr == addr)
            {
                continue;
            }
            match self
                .send_encrypted_link_message(&addr, &heartbeat_msg)
                .await
            {
                Ok(()) => {
                    self.peers.record_link_heartbeat_sent(&addr, now);
                }
                Err(e) => {
                    debug!(peer = %self.peer_display_name(&addr), error = %e, "Failed to send heartbeat");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
