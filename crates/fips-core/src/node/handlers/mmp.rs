//! MMP report dispatch, periodic report generation, and operator logging.
//!
//! Handles incoming SenderReport / ReceiverReport messages, drives
//! periodic report generation on the tick timer, and emits periodic
//! and teardown metric logs.

use crate::mmp::report::{ReceiverReport, SenderReport};
use crate::node::Node;
use crate::protocol::LinkMessageType;
use crate::{ActivePeer, NodeAddr};
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
    fn plan_link_heartbeat_tick<D, F, G>(
        &self,
        now: Instant,
        heartbeat_interval: Duration,
        max_rekey_resends: u32,
        mut defer_dead_peer_removal_for: D,
        mut effective_dead_timeout_for: F,
        mut quiet_for: G,
    ) -> LinkHeartbeatPlan
    where
        D: FnMut(&NodeAddr, &ActivePeer) -> bool,
        F: FnMut(&NodeAddr) -> Duration,
        G: FnMut(&NodeAddr, &ActivePeer) -> Duration,
    {
        let mut plan = LinkHeartbeatPlan::default();

        for (node_addr, peer) in self.iter() {
            if !peer.can_send() {
                continue;
            }

            let effective_dead_timeout = effective_dead_timeout_for(node_addr);
            let time_dead = if peer.noise_session().is_some() {
                quiet_for(node_addr, peer) >= effective_dead_timeout
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
                if defer_dead_peer_removal_for(node_addr, peer) {
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

impl Node {
    pub(crate) fn dataplane_fmp_link_metrics(
        &self,
        node_addr: &NodeAddr,
        now: Instant,
    ) -> Option<crate::dataplane::DataplaneFmpLinkMetrics> {
        self.dataplane.fmp_link_metrics(node_addr, now)
    }

    pub(crate) fn dataplane_fmp_link_cost(&self, node_addr: &NodeAddr) -> f64 {
        self.dataplane.fmp_link_cost(node_addr).unwrap_or(1.0)
    }

    pub(crate) fn dataplane_fmp_has_srtt(&self, node_addr: &NodeAddr) -> bool {
        self.dataplane.fmp_has_srtt(node_addr)
    }

    pub(crate) fn dataplane_fmp_peer_costs(&self) -> std::collections::HashMap<NodeAddr, f64> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.can_send())
            .filter(|(addr, _)| self.dataplane_fmp_has_srtt(addr))
            .map(|(addr, _)| (*addr, self.dataplane_fmp_link_cost(addr)))
            .collect()
    }

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

        if !self.dataplane_has_fmp_owner(from) {
            debug!(from = %self.peer_display_name(from), "SenderReport from unknown peer");
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

        let processed = match self.dataplane.process_fmp_mmp_receiver_report(
            from,
            &rr,
            Self::now_ms(),
            Instant::now(),
        ) {
            Ok(processed) => processed,
            Err(crate::dataplane::DataplaneFmpMmpSkip::UnknownOwner) => {
                debug!(from = %peer_name, "ReceiverReport from unknown peer");
                return;
            }
            Err(crate::dataplane::DataplaneFmpMmpSkip::MmpDisabled) => return,
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
            let peer_costs = self.dataplane_fmp_peer_costs();
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
        let batch = self.dataplane.collect_fmp_mmp_reports(Instant::now());

        for metrics in &batch.metric_logs {
            let peer_name = self.peer_display_name(&metrics.node_addr);
            Self::log_mmp_metrics(&peer_name, metrics);
        }

        for report in batch.reports {
            let report_name = match report.kind {
                crate::dataplane::DataplaneFmpMmpReportKind::Sender => "SenderReport",
                crate::dataplane::DataplaneFmpMmpReportKind::Receiver => "ReceiverReport",
            };
            if let Err(e) = self
                .send_dataplane_fmp_link_plaintext(&report.node_addr, &report.encoded, false)
                .await
            {
                debug!(peer = %self.peer_display_name(&report.node_addr), error = %e, report = report_name, "Failed to send MMP report");
            }
        }
    }

    /// Emit periodic MMP metrics for a peer.
    fn log_mmp_metrics(peer_name: &str, metrics: &crate::dataplane::DataplaneFmpLinkMetrics) {
        let rtt_str = metrics
            .srtt_ms
            .map(|rtt| format!("{rtt:.1}ms"))
            .unwrap_or_else(|| "n/a".to_string());
        let loss_str = metrics
            .loss_rate_for_log
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
    pub(in crate::node) fn log_mmp_teardown(
        peer_name: &str,
        metrics: &crate::dataplane::DataplaneFmpLinkMetrics,
    ) {
        let rtt_str = match metrics.srtt_ms {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };
        let loss_str = format!("{:.1}%", metrics.loss_rate * 100.0);

        debug!(
            peer = %peer_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", metrics.jitter_ms),
            etx = format_args!("{:.2}", metrics.etx),
            goodput = %format_throughput(metrics.goodput_bps),
            tx_pkts = metrics.tx_packets,
            tx_bytes = metrics.tx_bytes,
            rx_pkts = metrics.rx_packets,
            rx_bytes = metrics.rx_bytes,
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
        let batch = self.dataplane.collect_fsp_mmp_reports(now);

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
        for report in batch.reports {
            let success = match self
                .send_session_msg(&report.dest_addr, report.msg_type, &report.encoded)
                .await
            {
                Ok(()) => true,
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

                    false
                }
            };
            if let Some(resumed) = self
                .dataplane
                .record_fsp_mmp_send_result(report.dest_addr, success)
            {
                debug!(
                    dest = %self.peer_display_name(&resumed.dest_addr),
                    consecutive_failures = resumed.consecutive_failures,
                    "Resumed session MMP reporting"
                );
            }
        }
    }

    /// Emit periodic session MMP metrics.
    fn log_session_mmp_metrics(
        session_name: &str,
        metrics: &crate::dataplane::DataplaneFspMmpSnapshot,
    ) {
        let rtt_str = metrics
            .rtt_ms
            .map(|rtt| format!("{rtt:.1}ms"))
            .unwrap_or_else(|| "n/a".to_string());
        let loss_str = format!("{:.1}%", metrics.loss_rate * 100.0);

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
    pub(in crate::node) fn log_session_mmp_teardown(
        session_name: &str,
        mmp: &crate::dataplane::DataplaneFspMmpSnapshot,
    ) {
        let rtt_str = match mmp.rtt_ms {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };
        let loss_str = format!("{:.1}%", mmp.loss_rate * 100.0);

        debug!(
            session = %session_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", mmp.jitter_ms),
            etx = format_args!("{:.2}", mmp.etx),
            goodput = %format_throughput(mmp.goodput_bps),
            send_mtu = mmp.send_mtu,
            observed_mtu = mmp.observed_mtu,
            tx_pkts = mmp.tx_packets,
            tx_bytes = mmp.tx_bytes,
            rx_pkts = mmp.rx_packets,
            rx_bytes = mmp.rx_bytes,
            "MMP session teardown"
        );
    }

    pub(in crate::node) fn traversal_path_link_dead_timeout(
        &self,
        node_addr: &NodeAddr,
        dead_timeout: Duration,
        fast_dead_timeout: Duration,
    ) -> Option<Duration> {
        let peer_config = self.configured_peer(node_addr)?;
        if !peer_config.is_auto_connect() {
            return None;
        }
        if !self.active_peer_uses_traversal_path(node_addr, peer_config) {
            return None;
        }

        Some(traversal_path_liveness_timeout(
            self.config.node.heartbeat_interval_secs,
            dead_timeout,
            fast_dead_timeout,
        ))
    }

    pub(in crate::node) fn traversal_path_quiet_refresh_timeout(
        &self,
        node_addr: &NodeAddr,
        dead_timeout: Duration,
        fast_dead_timeout: Duration,
    ) -> Option<Duration> {
        let peer_config = self.configured_peer(node_addr)?;
        if !peer_config.is_auto_connect() {
            return None;
        }
        if !self.active_peer_uses_traversal_path(node_addr, peer_config) {
            return None;
        }

        Some(traversal_path_quiet_refresh_timeout(
            self.config.node.heartbeat_interval_secs,
            fast_dead_timeout,
            dead_timeout,
        ))
    }

    fn direct_path_liveness_quiet_for(
        &self,
        node_addr: &NodeAddr,
        peer: &ActivePeer,
        now: Instant,
        now_ms: u64,
    ) -> Duration {
        let mut quiet_for = self
            .dataplane
            .fmp_link_metrics(node_addr, now)
            .and_then(|metrics| metrics.last_recv_age_ms)
            .map(Duration::from_millis)
            .unwrap_or_else(|| now.duration_since(peer.session_start()));
        quiet_for = quiet_for.min(Duration::from_millis(peer.idle_time(now_ms)));

        if let Some(session_age_ms) = self
            .dataplane
            .min_fsp_rx_age_for_next_hop(node_addr, now_ms)
        {
            quiet_for = quiet_for.min(Duration::from_millis(session_age_ms));
        }

        if let Some(session_data_age_ms) = self
            .dataplane
            .min_fsp_data_rx_age_for_next_hop(node_addr, now_ms)
        {
            quiet_for = quiet_for.min(Duration::from_millis(session_data_age_ms));
        }

        quiet_for
    }

    /// Send heartbeats and remove dead peers.
    ///
    /// Called from the tick handler. Sends a 1-byte heartbeat to each peer
    /// whose heartbeat interval has elapsed, and removes any peer that
    /// hasn't sent us a frame within the link dead timeout.
    ///
    /// While the kernel has recently told us a non-traversal `transport.send`
    /// was locally unsendable (NetworkUnreachable / HostUnreachable /
    /// AddrNotAvailable), the dead-timeout collapses to
    /// `fast_link_dead_timeout_secs`. Traversal/recent endpoint paths keep
    /// their bounded heartbeat window because stale candidate errors can be
    /// transient and should not make a mobile/NAT path flap at the fast-dead
    /// floor.
    pub(in crate::node) async fn check_link_heartbeats(&mut self) {
        let now = Instant::now();
        let heartbeat_interval = Duration::from_secs(self.config.node.heartbeat_interval_secs);
        let dead_timeout = Duration::from_secs(self.config.node.link_dead_timeout_secs);
        let fast_dead_timeout = Duration::from_secs(self.config.node.fast_link_dead_timeout_secs);
        let max_rekey_resends = self.config.node.rate_limit.handshake_max_resends;
        self.purge_expired_local_send_failures(now);
        let defer_dead_peer_removal = self.rx_loop_maintenance_timed_out_recently();
        let heartbeat_msg = [LinkMessageType::Heartbeat.to_byte()];
        let now_ms = Self::now_ms();

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
                    .traversal_path_link_dead_timeout(node_addr, dead_timeout, fast_dead_timeout)
                    .unwrap_or(local_send_failure_timeout);
                (*node_addr, effective_dead_timeout)
            })
            .collect();
        let direct_path_quiet_for: std::collections::HashMap<NodeAddr, Duration> = self
            .peers
            .iter()
            .map(|(node_addr, peer)| {
                (
                    *node_addr,
                    self.direct_path_liveness_quiet_for(node_addr, peer, now, now_ms),
                )
            })
            .collect();
        let definitively_closed_paths: std::collections::HashSet<NodeAddr> = self
            .peers
            .iter()
            .filter_map(|(node_addr, peer)| {
                let transport_id = peer.transport_id()?;
                let remote_addr = peer.current_addr()?;
                let state = self
                    .get_transport(&transport_id)
                    .map(|transport| transport.connection_state(remote_addr));
                matches!(
                    state,
                    None | Some(crate::transport::ConnectionState::None)
                        | Some(crate::transport::ConnectionState::Failed(_))
                )
                .then_some(*node_addr)
            })
            .collect();
        let heartbeat_plan = self.peers.plan_link_heartbeat_tick(
            now,
            heartbeat_interval,
            max_rekey_resends,
            |node_addr, _| {
                defer_dead_peer_removal && !definitively_closed_paths.contains(node_addr)
            },
            |node_addr| {
                effective_dead_timeouts
                    .get(node_addr)
                    .copied()
                    .unwrap_or(dead_timeout)
            },
            |node_addr, peer| {
                direct_path_quiet_for
                    .get(node_addr)
                    .copied()
                    .unwrap_or_else(|| now.duration_since(peer.session_start()))
            },
        );

        let active_retry_peers = self
            .retry_pending
            .iter()
            .filter_map(|(node_addr, _)| self.peers.contains_key(node_addr).then_some(*node_addr))
            .collect::<Vec<_>>();
        for node_addr in active_retry_peers {
            let had_retry = self.retry_pending.contains_key(&node_addr);
            self.clear_retry_unless_direct_refresh_needed(&node_addr);
            if had_retry && !self.retry_pending.contains_key(&node_addr) {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    "Cleared direct-probe retry after authenticated traffic proved the active path fresh"
                );
            }
        }

        let quiet_traversal_peers: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(node_addr, peer)| {
                if !peer.is_healthy() || !peer.can_send() {
                    return None;
                }
                if heartbeat_plan
                    .dead_peers
                    .iter()
                    .chain(heartbeat_plan.deferred_dead_peers.iter())
                    .any(|dead_peer| dead_peer.node_addr == *node_addr)
                {
                    return None;
                }
                let refresh_timeout = self.traversal_path_quiet_refresh_timeout(
                    node_addr,
                    effective_dead_timeouts
                        .get(node_addr)
                        .copied()
                        .unwrap_or(dead_timeout),
                    fast_dead_timeout,
                )?;
                let quiet_for = direct_path_quiet_for
                    .get(node_addr)
                    .copied()
                    .unwrap_or_else(|| now.duration_since(peer.session_start()));
                (quiet_for >= refresh_timeout).then_some((*node_addr, quiet_for, refresh_timeout))
            })
            .collect();

        for dead_peer in &heartbeat_plan.deferred_dead_peers {
            debug!(
                peer = %self.peer_display_name(&dead_peer.node_addr),
                timeout_secs = dead_peer.effective_dead_timeout.as_secs(),
                "Deferring link-dead peer removal after recent rx-loop maintenance timeout"
            );
        }

        // Quiet traversal paths should refresh in the background, but they are
        // only de-prioritized for payload when recent session sends are not
        // getting authenticated return traffic.
        for (node_addr, quiet_for, refresh_timeout) in quiet_traversal_peers {
            let scheduled = self.schedule_quiet_traversal_reprobe(node_addr, now_ms);
            if scheduled {
                info!(
                    peer = %self.peer_display_name(&node_addr),
                    quiet_secs = quiet_for.as_secs(),
                    refresh_after_secs = refresh_timeout.as_secs(),
                    retry_scheduled = scheduled,
                    "Refreshing quiet traversal path in background before full link-dead timeout"
                );
            }
            if self.session_direct_path_exclusive_trust_expired(&node_addr, now_ms) {
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    quiet_secs = quiet_for.as_secs(),
                    refresh_after_secs = refresh_timeout.as_secs(),
                    "Warming fallback route for quiet traversal path with active unreturned session traffic"
                );
                self.maybe_initiate_direct_path_fallback_lookup(&node_addr)
                    .await;
            }
        }

        let unreturned_direct_payload_peers: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(node_addr, peer)| {
                if !peer.is_healthy() || !peer.can_send() {
                    return None;
                }
                if heartbeat_plan
                    .dead_peers
                    .iter()
                    .chain(heartbeat_plan.deferred_dead_peers.iter())
                    .any(|dead_peer| dead_peer.node_addr == *node_addr)
                {
                    return None;
                }
                self.session_direct_path_exclusive_trust_expired(node_addr, now_ms)
                    .then_some(*node_addr)
            })
            .collect();

        for node_addr in unreturned_direct_payload_peers {
            let selected_next_hop = self.find_next_hop(&node_addr).map(|peer| *peer.node_addr());
            if selected_next_hop.is_some_and(|next_hop| next_hop != node_addr) {
                continue;
            }
            if !self.has_sendable_fallback_lookup_peer(&node_addr) {
                continue;
            }

            debug!(
                peer = %self.peer_display_name(&node_addr),
                "Warming fallback lookup for path with fresh control but unreturned endpoint data"
            );
            self.maybe_initiate_path_recovery_lookup(&node_addr).await;
        }

        for dead_peer in &heartbeat_plan.dead_peers {
            warn!(
                peer = %self.peer_display_name(&dead_peer.node_addr),
                timeout_secs = dead_peer.effective_dead_timeout.as_secs(),
                fast = dead_peer.effective_dead_timeout < dead_timeout,
                "Marking direct path stale after link-dead timeout"
            );
            self.record_link_dead_path_failure(&dead_peer.node_addr, now_ms)
                .await;
            self.abandon_fmp_rekey_for_peer(&dead_peer.node_addr, "link-dead direct path");
            self.remove_link_dead_peer(&dead_peer.node_addr);
            self.schedule_link_dead_reprobe(dead_peer.node_addr, now_ms);
            if let Some(peer_config) = self
                .retry_pending
                .get(&dead_peer.node_addr)
                .map(|state| state.peer_config.clone())
            {
                match self
                    .initiate_active_peer_direct_refresh_connection(&peer_config)
                    .await
                {
                    Ok(true) => {
                        debug!(
                            peer = %self.peer_display_name(&dead_peer.node_addr),
                            "Started immediate direct-path refresh after link-dead timeout"
                        );
                    }
                    Ok(false) => {
                        debug!(
                            peer = %self.peer_display_name(&dead_peer.node_addr),
                            "Immediate direct-path refresh after link-dead timeout had no candidate"
                        );
                    }
                    Err(error) => {
                        debug!(
                            peer = %self.peer_display_name(&dead_peer.node_addr),
                            error = %error,
                            "Immediate direct-path refresh after link-dead timeout failed"
                        );
                    }
                }
            }
            self.maybe_initiate_direct_path_fallback_lookup(&dead_peer.node_addr)
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
                .send_dataplane_fmp_link_plaintext(&addr, &heartbeat_msg, false)
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

const TRAVERSAL_PATH_LIVENESS_FLOOR: Duration = Duration::from_secs(30);

pub(in crate::node) fn traversal_path_liveness_timeout(
    heartbeat_interval_secs: u64,
    dead_timeout: Duration,
    fast_dead_timeout: Duration,
) -> Duration {
    let heartbeat = Duration::from_secs(heartbeat_interval_secs.max(1));
    let recent_path_timeout = heartbeat
        .saturating_mul(3)
        .max(fast_dead_timeout)
        .max(TRAVERSAL_PATH_LIVENESS_FLOOR);
    recent_path_timeout.max(fast_dead_timeout).min(dead_timeout)
}

pub(in crate::node) fn traversal_path_quiet_refresh_timeout(
    heartbeat_interval_secs: u64,
    fast_dead_timeout: Duration,
    dead_timeout: Duration,
) -> Duration {
    let heartbeat = Duration::from_secs(heartbeat_interval_secs.max(1));
    let refresh_timeout = heartbeat.max(fast_dead_timeout.max(Duration::from_secs(1)));
    let dead_timeout =
        traversal_path_liveness_timeout(heartbeat_interval_secs, dead_timeout, fast_dead_timeout);
    let before_dead = dead_timeout
        .saturating_sub(Duration::from_secs(1))
        .max(Duration::from_secs(1));
    refresh_timeout.min(before_dead)
}

#[cfg(test)]
mod tests;
