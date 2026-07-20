impl Node {
    // === Session-layer MMP report handlers ===

    /// Handle an incoming session-layer SenderReport (msg_type 0x11).
    ///
    /// Informational only — the peer is telling us about what they sent.
    /// Logged but not used for metrics (same pattern as link-layer).
    fn handle_session_sender_report(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let sr = match SessionSenderReport::decode(body) {
            Ok(sr) => sr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionSenderReport");
                return;
            }
        };

        trace!(
            src = %self.peer_display_name(src_addr),
            cum_pkts = sr.cumulative_packets_sent,
            interval_bytes = sr.interval_bytes_sent,
            "Received SessionSenderReport"
        );
    }

    /// Handle an incoming session-layer ReceiverReport (msg_type 0x12).
    ///
    /// The peer is telling us about what they received from us. We feed
    /// this to our metrics to compute RTT, loss rate, and trend indicators.
    pub(in crate::node) async fn handle_session_receiver_report(
        &mut self,
        src_addr: &NodeAddr,
        body: &[u8],
    ) {
        let session_rr = match SessionReceiverReport::decode(body) {
            Ok(rr) => rr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionReceiverReport");
                return;
            }
        };

        // Convert to link-layer ReceiverReport for MmpMetrics processing
        let rr: ReceiverReport = ReceiverReport::from(&session_rr);

        let now_ms = Self::now_ms();
        let peer_name = self.peer_display_name(src_addr);
        let last_outbound_next_hop = self
            .dataplane
            .fsp_owner_activity(src_addr)
            .and_then(|activity| activity.last_outbound_next_hop());
        let processed = match self.dataplane.process_fsp_mmp_receiver_report(
            *src_addr,
            &rr,
            last_outbound_next_hop,
            now_ms,
            std::time::Instant::now(),
            SESSION_DIRECT_DEGRADED_MIN_SAMPLE,
        ) {
            Ok(processed) => ProcessedSessionReceiverReport {
                sample: processed.sample,
                used_direct_next_hop: processed.used_direct_next_hop,
                srtt_ms: processed.srtt_ms,
                route_quality_sample: session_receiver_report_can_drive_route_quality(
                    processed.mode,
                    processed.srtt_ms,
                ),
            },
            Err(crate::dataplane::DataplaneFspMmpSkip::UnknownOwner) => {
                debug!(src = %peer_name, "SessionReceiverReport for unknown session");
                return;
            }
            Err(crate::dataplane::DataplaneFspMmpSkip::MmpDisabled) => return,
        };

        if let Some((span, loss)) = processed.sample
            && processed.used_direct_next_hop
            && processed.route_quality_sample
            && span >= SESSION_DIRECT_DEGRADED_MIN_SAMPLE
        {
            if loss >= SESSION_DIRECT_DEGRADED_LOSS_THRESHOLD
                && self.peers.get(src_addr).is_some_and(|peer| peer.can_send())
            {
                let newly_degraded = self.mark_session_direct_path_degraded(*src_addr, now_ms);
                if newly_degraded || !self.retry_pending.contains_key(src_addr) {
                    self.schedule_link_dead_reprobe(*src_addr, now_ms);
                }
                debug!(
                    src = %peer_name,
                    loss = format_args!("{:.1}%", loss * 100.0),
                    sample_packets = span,
                    newly_degraded,
                    "Session loss marked direct path degraded; fallback routing may carry traffic while direct probes continue"
                );
                self.maybe_initiate_direct_path_fallback_lookup(src_addr)
                    .await;
            } else if loss <= SESSION_DIRECT_RECOVERY_LOSS_THRESHOLD
                && self.clear_session_direct_path_degraded(src_addr)
            {
                debug!(
                    src = %peer_name,
                    loss = format_args!("{:.1}%", loss * 100.0),
                    sample_packets = span,
                    "Session loss recovered; direct path eligible for normal routing"
                );
            }
        }

        trace!(
            src = %peer_name,
            rtt_ms = ?processed.srtt_ms,
            route_quality_sample = processed.route_quality_sample,
            loss = processed.sample
                .map(|(_, loss)| format!("{:.1}%", loss * 100.0))
                .unwrap_or_else(|| "n/a".to_string()),
            "Processed SessionReceiverReport"
        );
    }

    /// Handle an incoming PathMtuNotification (msg_type 0x13).
    ///
    /// The destination is telling us the path MTU has changed.
    /// Apply source-side rules (decrease immediate, increase validated).
    pub(in crate::node) fn handle_session_path_mtu_notification(
        &mut self,
        src_addr: &NodeAddr,
        body: &[u8],
    ) {
        let notif = match PathMtuNotification::decode(body) {
            Ok(n) => n,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed PathMtuNotification");
                return;
            }
        };

        let peer_name = self.peer_display_name(src_addr);
        let change = match self.apply_dataplane_fsp_path_mtu_signal(
            src_addr,
            notif.path_mtu,
            std::time::Instant::now(),
        ) {
            Ok(crate::dataplane::DataplaneFspPathMtuApplyResult::Changed(change)) => change,
            Ok(crate::dataplane::DataplaneFspPathMtuApplyResult::Unchanged) => return,
            Err(crate::dataplane::DataplaneFspMmpSkip::UnknownOwner) => {
                debug!(src = %peer_name, "PathMtuNotification for unknown session");
                return;
            }
            Err(crate::dataplane::DataplaneFspMmpSkip::MmpDisabled) => return,
        };

        debug!(
            src = %peer_name,
            old_mtu = change.old_mtu,
            new_mtu = change.new_mtu,
            "Path MTU changed via notification"
        );

        // Mirror the new effective MTU into the FipsAddress-keyed lookup used
        // by the TUN reader/writer at TCP MSS clamp time. Without this, new
        // TCP flows opened on a path the proactive end-to-end echo has
        // already tightened keep getting clamped by the staler discovery-
        // time value until a reactive MtuExceeded happens to fire. Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::FipsAddress::from_node_addr(src_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => match map.get(&fips_addr).copied() {
                Some(existing) if existing <= change.new_mtu => {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu = change.new_mtu,
                        existing,
                        "PathMtuNotification: keeping tighter existing path_mtu_lookup value"
                    );
                }
                other => {
                    map.insert(fips_addr, change.new_mtu);
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu = change.new_mtu,
                        prior = ?other,
                        map_len = map.len(),
                        "PathMtuNotification: tightened path_mtu_lookup"
                    );
                }
            },
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    new_mtu = change.new_mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; PathMtuNotification not reflected"
                );
            }
        }
    }

    /// Handle a CoordsRequired error signal from a transit router.
    ///
    /// The router couldn't route our packet because it lacks cached
    /// coordinates for the destination. Send a standalone CoordsWarmup
    /// immediately (rate-limited), trigger discovery, and reset the
    /// warmup counter for subsequent data packets.
    async fn handle_coords_required(&mut self, previous_hop: &NodeAddr, inner: &[u8]) {
        self.stats_mut().errors.coords_required += 1;

        let msg = match CoordsRequired::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed CoordsRequired");
                return;
            }
        };

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "CoordsRequired: transit router needs coordinates"
        );

        if !self.routing_error_matches_active_path(&msg.dest_addr, previous_hop) {
            debug!(
                dest = %msg.dest_addr,
                reporter = %msg.reporter,
                previous_hop = %previous_hop,
                "Ignoring CoordsRequired from a stale route branch"
            );
            return;
        }

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr)
        {
            if self.dataplane_has_fsp_owner(&msg.dest_addr)
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to CoordsRequired");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "CoordsRequired response rate-limited, skipping standalone CoordsWarmup");
        }

        // Only trigger discovery if we have the target's identity cached —
        // otherwise we can't verify the LookupResponse proof.
        if self.has_cached_identity(&msg.dest_addr) {
            self.maybe_initiate_lookup(&msg.dest_addr).await;
        } else {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after CoordsRequired: no cached identity for target");
        }

        // Reset coords warmup counter so the next N packets also include
        // COORDS_PRESENT, re-warming transit caches along the path.
        let n = self.config.node.session.coords_warmup_packets;
        if self.refresh_dataplane_fsp_owner_routes_with_coords_warmup(&msg.dest_addr, n) {
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after CoordsRequired"
            );
        }
    }

    /// Handle a PathBroken error signal from a transit router.
    ///
    /// The router has coordinates but still can't route to the destination.
    /// Send a standalone CoordsWarmup immediately (rate-limited), invalidate
    /// cached coordinates, trigger re-discovery, and reset the warmup counter.
    async fn handle_path_broken(&mut self, previous_hop: &NodeAddr, inner: &[u8]) {
        self.stats_mut().errors.path_broken += 1;

        let msg = match PathBroken::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed PathBroken");
                return;
            }
        };

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "PathBroken: transit router reports routing failure"
        );

        // PathBroken invalidates cached routing state, so only the
        // authenticated adjacent hop may author it. CoordsRequired above is
        // non-destructive recovery feedback and may legitimately come from a
        // downstream router on the pinned multi-hop path.
        if msg.reporter != *previous_hop
            || !self.routing_error_matches_active_path(&msg.dest_addr, previous_hop)
        {
            debug!(
                dest = %msg.dest_addr,
                reporter = %msg.reporter,
                previous_hop = %previous_hop,
                "Ignoring PathBroken from a stale route branch"
            );
            return;
        }

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr)
        {
            if self.dataplane_has_fsp_owner(&msg.dest_addr)
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to PathBroken");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "PathBroken response rate-limited, skipping standalone CoordsWarmup");
        }

        // Invalidate stale cached coordinates
        self.coord_cache.remove(&msg.dest_addr);

        // Trigger re-discovery to get fresh coordinates, but only if we have
        // the target's identity cached — otherwise we can't verify the
        // LookupResponse proof. This avoids a race when the XK responder
        // receives PathBroken before msg3 completes (identity unknown).
        if self.has_cached_identity(&msg.dest_addr) {
            self.maybe_initiate_lookup(&msg.dest_addr).await;
        } else {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after PathBroken: no cached identity for target");
        }

        // Reset coords warmup counter so the next N packets include
        // COORDS_PRESENT, re-warming transit caches along the new path.
        let n = self.config.node.session.coords_warmup_packets;
        if self.refresh_dataplane_fsp_owner_routes_with_coords_warmup(&msg.dest_addr, n) {
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after PathBroken"
            );
        }
    }

    /// Handle an MtuExceeded error signal from a transit router.
    ///
    /// A transit router couldn't forward our packet because it exceeded the
    /// next-hop transport MTU. Apply the reported bottleneck MTU to our
    /// PathMtuState for the affected session, causing an immediate decrease.
    pub(in crate::node) async fn handle_mtu_exceeded(&mut self, inner: &[u8]) {
        self.stats_mut().errors.mtu_exceeded += 1;

        let msg = match MtuExceeded::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed MtuExceeded");
                return;
            }
        };

        let peer_name = self.peer_display_name(&msg.dest_addr);
        debug!(
            dest = %peer_name,
            reporter = %msg.reporter,
            bottleneck_mtu = msg.mtu,
            "MtuExceeded: transit router reports oversized packet"
        );

        // Apply to PathMtuState: immediate decrease via apply_notification()
        match self.apply_dataplane_fsp_path_mtu_signal(
            &msg.dest_addr,
            msg.mtu,
            std::time::Instant::now(),
        ) {
            Ok(crate::dataplane::DataplaneFspPathMtuApplyResult::Changed(change)) => {
                info!(
                    dest = %peer_name,
                    old_mtu = change.old_mtu,
                    new_mtu = change.new_mtu,
                    reporter = %msg.reporter,
                    "Path MTU decreased via reactive MtuExceeded signal"
                );
            }
            Ok(crate::dataplane::DataplaneFspPathMtuApplyResult::Unchanged)
            | Err(crate::dataplane::DataplaneFspMmpSkip::UnknownOwner)
            | Err(crate::dataplane::DataplaneFspMmpSkip::MmpDisabled) => {}
        };

        // Mirror the bottleneck into the FipsAddress-keyed lookup used by
        // the TUN reader/writer at TCP MSS clamp time. Discovery's reverse-
        // path response can carry a value too generous for the actual
        // forward path; the reactive signal from a forwarder that actually
        // dropped a packet is authoritative for "what fits". Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::FipsAddress::from_node_addr(&msg.dest_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => match map.get(&fips_addr).copied() {
                Some(existing) if existing <= msg.mtu => {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        existing,
                        "Reactive MtuExceeded: keeping tighter existing path_mtu_lookup value"
                    );
                }
                other => {
                    map.insert(fips_addr, msg.mtu);
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        prior = ?other,
                        map_len = map.len(),
                        "Reactive MtuExceeded: tightened path_mtu_lookup"
                    );
                }
            },
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    bottleneck_mtu = msg.mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; reactive MtuExceeded not reflected"
                );
            }
        }
    }

}
