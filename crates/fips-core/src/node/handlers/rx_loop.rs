//! RX event loop and packet dispatch.

use crate::control::queries;
use crate::control::{ControlSocket, commands};
use crate::discovery::is_punch_packet;
use crate::node::decrypt_worker::{
    DecryptFailureReport, DecryptFallback, DecryptWorkerEvent, DecryptWorkerFallbackReceivers,
};
use crate::node::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FLAG_CE, FLAG_SP, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1,
    PHASE_MSG2,
};
use crate::node::{Node, NodeEndpointCommand, NodeError};
use crate::transport::ReceivedPacket;
use crate::transport::TransportHandle;
use crate::upper::tun::TunOutboundRx;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, UnboundedReceiver};
use tracing::{debug, info, trace, warn};

/// How often the raw-packet drain loop yields a slice of work to the
/// decrypt-fallback drain. Keeps TCP ACK / heartbeat / handshake
/// progress steady under sustained inbound bursts.
const FALLBACK_INTERLEAVE_EVERY: usize = 32;
/// Cap on the per-interleave fallback drain so a hot inbound spike
/// can't starve the outer raw-packet drain in the opposite direction.
const FALLBACK_INTERLEAVE_BUDGET: usize = 64;
const PACKET_DRAIN_BUDGET: usize = 256;
const RX_LOOP_SLOW_MAINTENANCE_IDLE_TIMEOUT: Duration = Duration::from_millis(100);
const RX_LOOP_SLOW_MAINTENANCE_BUSY_TIMEOUT: Duration = Duration::from_millis(10);
const RX_LOOP_RECENT_DATA_ACTIVITY_WINDOW: Duration = Duration::from_secs(2);
const RX_LOOP_FAULT_MAX_DELAY_MS: u64 = 5_000;

fn rx_loop_slow_maintenance_fault_delay() -> Option<Duration> {
    let raw = std::env::var("FIPS_FAULT_INJECT_RX_LOOP_SLOW_MAINTENANCE_MS").ok()?;
    let ms = raw
        .trim()
        .parse::<u64>()
        .ok()?
        .min(RX_LOOP_FAULT_MAX_DELAY_MS);
    (ms > 0).then(|| Duration::from_millis(ms))
}

impl Node {
    /// Run the receive event loop.
    ///
    /// Processes packets from all transports, dispatching based on
    /// the phase field in the 4-byte common prefix:
    /// - Phase 0x0: Encrypted frame (session data)
    /// - Phase 0x1: Handshake message 1 (initiator -> responder)
    /// - Phase 0x2: Handshake message 2 (responder -> initiator)
    ///
    /// Also processes outbound IPv6 packets from the TUN reader for session
    /// encapsulation and routing through the mesh.
    ///
    /// Also processes DNS-resolved identities for identity cache population.
    ///
    /// Also runs a periodic tick (1s) to clean up stale handshake connections
    /// that never received a response. This prevents resource leaks when peers
    /// are unreachable.
    ///
    /// This method takes ownership of the packet_rx channel and runs
    /// until the channel is closed (typically when stop() is called).
    pub async fn run_rx_loop(&mut self) -> Result<(), NodeError> {
        let mut packet_rx = self.packet_rx.take().ok_or(NodeError::NotStarted)?;

        // Take the TUN outbound receiver, or create a dummy channel that never
        // produces messages (when TUN is disabled). Holding the sender prevents
        // the channel from closing.
        let (mut tun_outbound_rx, _tun_guard) = match self.tun_outbound_rx.take() {
            Some(rx) => (rx, None),
            None => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                (rx, Some(tx))
            }
        };

        // Take the DNS identity receiver, or create a dummy channel (when DNS
        // is disabled). Same pattern as TUN outbound.
        let (mut dns_identity_rx, _dns_guard) = match self.dns_identity_rx.take() {
            Some(rx) => (rx, None),
            None => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                (rx, Some(tx))
            }
        };

        // Take the endpoint-data command receiver, or create a dummy channel
        // when the embedded endpoint API is not in use.
        let (mut endpoint_priority_command_rx, _endpoint_priority_command_guard) =
            match self.endpoint_priority_command_rx.take() {
                Some(rx) => (rx, None),
                None => {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    (rx, Some(tx))
                }
            };
        let (mut endpoint_command_rx, _endpoint_command_guard) =
            match self.endpoint_command_rx.take() {
                Some(rx) => (rx, None),
                None => {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    (rx, Some(tx))
                }
            };

        // Take the decrypt worker fallback receiver if a worker pool
        // is in use. The worker pushes non-fast-path packets (anything
        // that's not bulk EndpointData) here for the legacy dispatch.
        let (mut decrypt_fallback_rx, _decrypt_fallback_guard) =
            match self.decrypt_fallback_rx.take() {
                Some(rx) => (rx, None),
                None => {
                    let (tx, rx) = crate::node::decrypt_worker::decrypt_worker_fallback_channels();
                    (rx, Some(tx))
                }
            };

        let mut tick =
            tokio::time::interval(Duration::from_secs(self.config.node.tick_interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut maintenance_state = RxLoopMaintenanceState::default();

        // Set up control socket channel
        let (control_tx, mut control_rx) =
            tokio::sync::mpsc::channel::<crate::control::ControlMessage>(32);

        if self.config.node.control.enabled {
            let config = self.config.node.control.clone();
            let tx = control_tx.clone();
            tokio::spawn(async move {
                match ControlSocket::bind(&config) {
                    Ok(socket) => {
                        socket.accept_loop(tx).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to bind control socket");
                    }
                }
            });
        }
        // Drop unused sender to avoid keeping channel open if control is disabled
        drop(control_tx);

        info!("RX event loop started");
        // Optional perf profiler (FIPS_PERF=1). No-op otherwise.
        crate::perf_profile::maybe_spawn_reporter();

        loop {
            tokio::select! {
                biased;
                // Decrypt-worker fallback drains FIRST. The previous
                // ordering put `packet_rx` first, which under sustained
                // inbound bursts let the raw-packet drain (up to 256
                // packets + flush) starve fallback work for tens of
                // milliseconds. UDP throughput tolerates that; TCP
                // doesn't — late FMP plaintexts mean late ACKs,
                // dup-ACK fast retransmits, and cwnd collapse.
                // Reproduced on native macOS / Wi-Fi where TCP fell to
                // ~10 Mb/s while UDP cleared ~100 Mb/s on the same
                // tunnel. Promoting fallback gives the kernel-side
                // TCP machinery a fair chance to see its ACKs and
                // keep cwnd growing.
                Some(event) = decrypt_fallback_rx.priority.recv() => {
                    self.drain_decrypt_fallback(
                        &mut decrypt_fallback_rx,
                        Some(event),
                        None,
                        PACKET_DRAIN_BUDGET,
                    ).await;
                    maintenance_state.record_data_activity(Instant::now());
                    self.flush_pending_sends().await;
                }
                Some(event) = decrypt_fallback_rx.bulk.recv() => {
                    self.drain_decrypt_fallback(
                        &mut decrypt_fallback_rx,
                        None,
                        Some(event),
                        PACKET_DRAIN_BUDGET,
                    ).await;
                    maintenance_state.record_data_activity(Instant::now());
                    self.flush_pending_sends().await;
                }
                packet = packet_rx.recv() => {
                    match packet {
                        Some(p) => {
                            let drained = self.drain_packet_rx(
                                &mut packet_rx,
                                &mut decrypt_fallback_rx,
                                Some(p),
                                PACKET_DRAIN_BUDGET,
                            ).await;
                            if drained > 0 {
                                maintenance_state.record_data_activity(Instant::now());
                            }
                        }
                        None => break, // channel closed
                    }
                }
                _ = tick.tick() => {
                    let drained = self.drain_rx_loop_data_queues(
                        &mut packet_rx,
                        &mut decrypt_fallback_rx,
                        &mut tun_outbound_rx,
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        PACKET_DRAIN_BUDGET,
                    ).await;
                    if drained.has_drained() {
                        maintenance_state.record_data_activity(Instant::now());
                        debug!(
                            drained = drained.total(),
                            drained_packets = drained.packets,
                            drained_tun = drained.tun,
                            drained_endpoint = drained.endpoint,
                            "Drained queued packets before rx-loop maintenance"
                        );
                    }
                    let maintenance_plan = maintenance_state.plan_maintenance(
                        drained,
                        Instant::now(),
                        RX_LOOP_RECENT_DATA_ACTIVITY_WINDOW,
                        RX_LOOP_SLOW_MAINTENANCE_IDLE_TIMEOUT,
                        RX_LOOP_SLOW_MAINTENANCE_BUSY_TIMEOUT,
                    );

                    let slow_timed_out = self.run_rx_loop_maintenance_tick(
                        maintenance_plan,
                    ).await;
                    maintenance_state.record_maintenance_result(
                        maintenance_plan.data_pressure(),
                        slow_timed_out,
                    );

                    let post_drained = self.drain_rx_loop_data_queues(
                        &mut packet_rx,
                        &mut decrypt_fallback_rx,
                        &mut tun_outbound_rx,
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        PACKET_DRAIN_BUDGET,
                    ).await;
                    if post_drained.has_drained() {
                        maintenance_state.record_data_activity(Instant::now());
                        debug!(
                            drained = post_drained.total(),
                            drained_packets = post_drained.packets,
                            drained_tun = post_drained.tun,
                            drained_endpoint = post_drained.endpoint,
                            "Drained queued packets after rx-loop maintenance"
                        );
                    }
                }
                Some(ipv6_packet) = tun_outbound_rx.recv() => {
                    let drained = self.drain_tun_outbound(
                        &mut tun_outbound_rx,
                        Some(ipv6_packet),
                        PACKET_DRAIN_BUDGET,
                    ).await;
                    if drained > 0 {
                        maintenance_state.record_data_activity(Instant::now());
                    }
                }
                Some(identity) = dns_identity_rx.recv() => {
                    debug!(
                        node_addr = %identity.node_addr,
                        "Registering identity from DNS resolution"
                    );
                    self.register_identity(identity.node_addr, identity.pubkey);
                }
                Some(command) = endpoint_priority_command_rx.recv() => {
                    let drained = self.drain_endpoint_commands(
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        Some(command),
                        None,
                        PACKET_DRAIN_BUDGET,
                    ).await;
                    if drained > 0 {
                        maintenance_state.record_data_activity(Instant::now());
                    }
                }
                Some(command) = endpoint_command_rx.recv() => {
                    let drained = self.drain_endpoint_commands(
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        None,
                        Some(command),
                        PACKET_DRAIN_BUDGET,
                    ).await;
                    if drained > 0 {
                        maintenance_state.record_data_activity(Instant::now());
                    }
                }
                Some((request, response_tx)) = control_rx.recv() => {
                    let response = if request.command.starts_with("show_") {
                        queries::dispatch(self, &request.command, request.params.as_ref())
                    } else {
                        commands::dispatch(
                            self,
                            &request.command,
                            request.params.as_ref(),
                        ).await
                    };
                    let _ = response_tx.send(response);
                }
            }
        }

        info!("RX event loop stopped (channel closed)");
        Ok(())
    }

    async fn drain_rx_loop_data_queues(
        &mut self,
        packet_rx: &mut UnboundedReceiver<ReceivedPacket>,
        decrypt_fallback_rx: &mut DecryptWorkerFallbackReceivers,
        tun_outbound_rx: &mut TunOutboundRx,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        budget: usize,
    ) -> RxLoopDataDrainStats {
        let drained_packets = self
            .drain_packet_rx(packet_rx, decrypt_fallback_rx, None, budget)
            .await;
        let drained_tun = self.drain_tun_outbound(tun_outbound_rx, None, budget).await;
        let drained_endpoint = self
            .drain_endpoint_commands(
                endpoint_priority_command_rx,
                endpoint_command_rx,
                None,
                None,
                budget,
            )
            .await;
        RxLoopDataDrainStats::new(drained_packets, drained_tun, drained_endpoint)
    }

    async fn drain_packet_rx(
        &mut self,
        packet_rx: &mut UnboundedReceiver<ReceivedPacket>,
        decrypt_fallback_rx: &mut DecryptWorkerFallbackReceivers,
        first_packet: Option<ReceivedPacket>,
        budget: usize,
    ) -> usize {
        // Drain remaining ready inbound packets in a tight loop before
        // yielding back to select! Every yield is a scheduler hop, and at
        // line rate transports typically have several packets available per
        // wake. Caps at a batch boundary so other branches eventually get a
        // turn even under sustained load.
        let mut drain = PacketDrainCursor::new(first_packet, budget, FALLBACK_INTERLEAVE_EVERY);
        while let Some(action) = drain.next(packet_rx) {
            match action {
                PacketDrainAction::Packet(packet) => {
                    self.process_packet(packet).await;
                }
                PacketDrainAction::InterleaveFallback => {
                    self.drain_decrypt_fallback(
                        decrypt_fallback_rx,
                        None,
                        None,
                        FALLBACK_INTERLEAVE_BUDGET,
                    )
                    .await;
                }
            }
        }

        let drained = drain.drained();
        if drained > 0 {
            // One trailing fallback drain so the last bounced packets of the
            // burst aren't held up by the post-burst send flush.
            self.drain_decrypt_fallback(decrypt_fallback_rx, None, None, PACKET_DRAIN_BUDGET)
                .await;
            // Flush any batched sends triggered by inbound packets (e.g.
            // forwarded SessionDatagrams, MMP reports, tree announces).
            self.flush_pending_sends().await;
        }
        drained
    }

    async fn drain_tun_outbound(
        &mut self,
        tun_outbound_rx: &mut TunOutboundRx,
        first_packet: Option<Vec<u8>>,
        budget: usize,
    ) -> usize {
        let mut drain = TunOutboundDrainCursor::new(first_packet, budget);
        while let Some(packet) = drain.next(tun_outbound_rx) {
            self.handle_tun_outbound(packet).await;
        }

        let drained = drain.drained();
        if drained > 0 {
            self.flush_pending_sends().await;
        }
        drained
    }

    async fn drain_endpoint_commands(
        &mut self,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        first_priority_command: Option<NodeEndpointCommand>,
        first_bulk_command: Option<NodeEndpointCommand>,
        budget: usize,
    ) -> usize {
        let mut drain =
            PriorityBulkDrainCursor::new(first_priority_command, first_bulk_command, budget);
        while let Some(command) = drain.next(endpoint_priority_command_rx, endpoint_command_rx) {
            let drain_cost = command.drain_cost();
            self.handle_endpoint_data_command(command).await;
            drain.charge_extra(drain_cost.saturating_sub(1));
        }

        let drained = drain.drained();
        if drained > 0 {
            self.flush_pending_sends().await;
        }
        drained
    }

    async fn run_rx_loop_maintenance_tick(&mut self, plan: RxLoopMaintenancePlan) -> bool {
        self.check_timeouts();
        let now_ms = Self::now_ms();
        // Link/session liveness must run before slower retry/discovery work:
        // under bulk send pressure a late heartbeat or MMP report is
        // indistinguishable from a dead direct path on the remote peer.
        self.check_link_heartbeats().await;
        self.reload_peer_acl();
        self.resend_pending_handshakes(now_ms).await;
        self.resend_pending_rekeys(now_ms).await;
        self.resend_pending_session_handshakes(now_ms).await;
        self.resend_pending_session_msg3(now_ms).await;
        self.purge_idle_sessions(now_ms);
        self.purge_learned_routes(now_ms);
        self.check_mmp_reports().await;
        self.check_session_mmp_reports().await;
        self.check_rekey().await;
        self.check_session_rekey().await;
        self.check_pending_lookups(now_ms).await;
        self.poll_pending_connects().await;
        self.process_pending_retries(now_ms).await;
        self.poll_transport_discovery().await;
        self.activate_connected_udp_sessions().await;
        self.sample_transport_congestion();

        let Some(slow_timeout) = plan.slow_timeout() else {
            return false;
        };

        if tokio::time::timeout(slow_timeout, self.run_rx_loop_slow_maintenance_tick())
            .await
            .is_err()
        {
            self.mark_rx_loop_maintenance_timeout();
            warn!(
                timeout_ms = slow_timeout.as_millis() as u64,
                data_pressure = plan.data_pressure(),
                "RX loop slow maintenance timed out; continuing packet processing"
            );
            return true;
        }
        false
    }

    async fn run_rx_loop_slow_maintenance_tick(&mut self) {
        if let Some(delay) = rx_loop_slow_maintenance_fault_delay() {
            tokio::time::sleep(delay).await;
        }

        // Discovery and graph/stat maintenance can involve relay work or
        // larger scans. Keep it bounded after direct-path liveness and session
        // upkeep so a slow Nostr/LAN tick degrades discovery freshness, not
        // packet flow.
        self.poll_nostr_discovery().await;
        self.poll_lan_discovery().await;
        self.poll_local_instance_discovery().await;
        self.check_tree_state().await;
        self.check_bloom_state().await;
        self.compute_mesh_size();
        self.record_stats_history();
    }

    /// Hand a decrypt-worker fallback to the canonical post-FMP-decrypt
    /// processor. Reconstructs `ce_flag` / `sp_flag` from the FMP header
    /// flag byte the worker captured into `DecryptFallback::fmp_flags`
    /// (without this both ECN CE propagation and spin-bit RTT
    /// observation are dropped on the worker path) and slices the
    /// plaintext out of the original wire buffer with zero allocation.
    async fn process_decrypt_worker_event(&mut self, event: DecryptWorkerEvent) {
        match event {
            DecryptWorkerEvent::Plaintext(fallback) => {
                self.process_decrypt_fallback(fallback).await;
            }
            DecryptWorkerEvent::DecryptFailure(report) => {
                self.process_decrypt_failure_report(report).await;
            }
        }
    }

    async fn process_decrypt_fallback(&mut self, fallback: DecryptFallback) {
        let ce_flag = fallback.fmp_flags & FLAG_CE != 0;
        let sp_flag = fallback.fmp_flags & FLAG_SP != 0;
        let plaintext = &fallback.packet_data[fallback.fmp_plaintext_offset
            ..fallback.fmp_plaintext_offset + fallback.fmp_plaintext_len];
        self.process_authentic_fmp_plaintext(
            &fallback.source_node_addr,
            fallback.transport_id,
            &fallback.remote_addr,
            fallback.timestamp_ms,
            fallback.packet_len,
            fallback.fmp_counter,
            ce_flag,
            sp_flag,
            plaintext,
        )
        .await;
    }

    async fn process_decrypt_failure_report(&mut self, report: DecryptFailureReport) {
        debug!(
            peer = %self.peer_display_name(&report.source_node_addr),
            counter = report.fmp_counter,
            replay_highest = report.fmp_replay_highest,
            "Worker FMP AEAD decryption failed"
        );
        self.handle_decrypt_failure_report(&report).await;
    }

    /// Drain up to `budget` queued fallbacks without yielding back to
    /// `select!`. Returns the number processed. Called both from the
    /// promoted-fallback select arm (after the head item) and
    /// interleaved inside the packet_rx drain loop so bounced FMP
    /// plaintexts can't accumulate behind a 256-packet inbound burst.
    async fn drain_decrypt_fallback(
        &mut self,
        rx: &mut DecryptWorkerFallbackReceivers,
        first_priority_event: Option<DecryptWorkerEvent>,
        first_bulk_event: Option<DecryptWorkerEvent>,
        budget: usize,
    ) -> usize {
        let mut drain =
            PriorityBulkDrainCursor::new(first_priority_event, first_bulk_event, budget);
        while let Some(event) = drain.next(&mut rx.priority, &mut rx.bulk) {
            self.process_decrypt_worker_event(event).await;
        }
        drain.drained()
    }

    /// Flush any pending batched sends across all transports. Today
    /// every transport's `flush_pending_send` is a no-op — the UDP
    /// transport's per-transport `pending_send` buffer was removed
    /// when the bulk data path moved into `encrypt_worker` (which
    /// does its own target-grouped `sendmmsg(2)` directly). The
    /// call sites are retained so any future batched transport can
    /// opt in by overriding `flush_pending_send` without touching
    /// the rx_loop.
    async fn flush_pending_sends(&self) {
        for transport in self.transports.values() {
            if matches!(transport, TransportHandle::Udp(_)) {
                transport.flush_pending_send().await;
            }
        }
    }

    /// Process a single received packet.
    ///
    /// Dispatches based on the phase field in the 4-byte common prefix.
    pub(in crate::node) async fn process_packet(&mut self, packet: ReceivedPacket) {
        let _t_total = crate::perf_profile::Timer::start(crate::perf_profile::Stage::ProcessPacket);
        crate::perf_profile::record_since(
            crate::perf_profile::Stage::TransportQueueWait,
            packet.trace_enqueued_at,
        );
        if is_punch_packet(&packet.data) {
            trace!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                "Dropping stray punch probe/ack in FMP rx loop"
            );
            return;
        }
        if packet.data.len() < COMMON_PREFIX_SIZE {
            return; // Drop packets too short for common prefix
        }

        let prefix = match CommonPrefix::parse(&packet.data) {
            Some(p) => p,
            None => return, // Malformed prefix
        };
        if matches!(prefix.phase, PHASE_MSG1 | PHASE_MSG2) {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                phase = prefix.phase,
                version = prefix.version,
                "FMP handshake packet dispatch"
            );
        } else {
            trace!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                phase = prefix.phase,
                version = prefix.version,
                "FMP packet dispatch"
            );
        }

        if prefix.version != FMP_VERSION {
            debug!(
                version = prefix.version,
                transport_id = %packet.transport_id,
                "Unknown FMP version, dropping"
            );

            // If the packet arrived on an adopted Nostr-NAT bootstrap
            // transport, the originating peer is necessarily on a
            // different FMP-protocol version than us — the discovery
            // sweep would otherwise re-traverse them every cycle even
            // though no msg1/msg2 exchange can ever succeed. Bump the
            // discovery-layer cooldown to the long protocol-mismatch
            // window and emit a single WARN per fresh observation.
            let looks_like_fmp_phase =
                matches!(prefix.phase, PHASE_ESTABLISHED | PHASE_MSG1 | PHASE_MSG2);
            if looks_like_fmp_phase
                && self.bootstrap_transports.contains(&packet.transport_id)
                && let Some(npub) = self.bootstrap_transports.peer_npub(&packet.transport_id)
                && let Some(handle) = self.nostr_discovery_handle()
            {
                let now_ms = Self::now_ms();
                let cooldown_secs = handle.protocol_mismatch_cooldown_secs();
                if handle.record_protocol_mismatch(npub, now_ms) {
                    warn!(
                        peer_npub = %npub,
                        transport_id = %packet.transport_id,
                        peer_version = prefix.version,
                        our_version = FMP_VERSION,
                        cooldown_secs,
                        "Nostr-discovered peer speaks a different FMP version; suppressing retraversal"
                    );
                }
            }
            return;
        }

        match prefix.phase {
            PHASE_ESTABLISHED => {
                self.handle_encrypted_frame(packet).await;
            }
            PHASE_MSG1 => {
                self.handle_msg1(packet).await;
            }
            PHASE_MSG2 => {
                self.handle_msg2(packet).await;
            }
            _ => {
                debug!(
                    phase = prefix.phase,
                    transport_id = %packet.transport_id,
                    "Unknown FMP phase, dropping"
                );
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PacketDrainAction<T> {
    Packet(T),
    InterleaveFallback,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RxLoopDataDrainStats {
    packets: usize,
    tun: usize,
    endpoint: usize,
}

impl RxLoopDataDrainStats {
    fn new(packets: usize, tun: usize, endpoint: usize) -> Self {
        Self {
            packets,
            tun,
            endpoint,
        }
    }

    fn total(&self) -> usize {
        self.packets + self.tun + self.endpoint
    }

    fn has_drained(&self) -> bool {
        self.total() > 0
    }

    fn data_pressure(&self, recent_data_activity: bool) -> bool {
        self.has_drained() || recent_data_activity
    }
}

#[derive(Debug, Default)]
struct RxLoopMaintenanceState {
    last_data_activity: Option<Instant>,
    slow_maintenance_timed_out_under_data: bool,
}

impl RxLoopMaintenanceState {
    fn record_data_activity(&mut self, now: Instant) {
        self.last_data_activity = Some(now);
    }

    fn data_pressure(
        &self,
        drained: RxLoopDataDrainStats,
        now: Instant,
        activity_window: Duration,
    ) -> bool {
        drained.data_pressure(self.recent_data_activity(now, activity_window))
    }

    fn skip_slow_maintenance(&self, data_pressure: bool) -> bool {
        data_pressure && self.slow_maintenance_timed_out_under_data
    }

    fn plan_maintenance(
        &self,
        drained: RxLoopDataDrainStats,
        now: Instant,
        activity_window: Duration,
        idle_timeout: Duration,
        busy_timeout: Duration,
    ) -> RxLoopMaintenancePlan {
        let data_pressure = self.data_pressure(drained, now, activity_window);
        RxLoopMaintenancePlan::new(
            data_pressure,
            self.skip_slow_maintenance(data_pressure),
            idle_timeout,
            busy_timeout,
        )
    }

    fn record_maintenance_result(&mut self, data_pressure: bool, slow_timed_out: bool) {
        if !data_pressure {
            self.slow_maintenance_timed_out_under_data = false;
        } else if slow_timed_out {
            self.slow_maintenance_timed_out_under_data = true;
        }
    }

    fn recent_data_activity(&self, now: Instant, activity_window: Duration) -> bool {
        self.last_data_activity
            .is_some_and(|last| now.saturating_duration_since(last) <= activity_window)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RxLoopMaintenancePlan {
    data_pressure: bool,
    slow_timeout: Option<Duration>,
}

impl RxLoopMaintenancePlan {
    fn new(
        data_pressure: bool,
        skip_slow_maintenance: bool,
        idle_timeout: Duration,
        busy_timeout: Duration,
    ) -> Self {
        let slow_timeout = if data_pressure && skip_slow_maintenance {
            None
        } else if data_pressure {
            Some(busy_timeout)
        } else {
            Some(idle_timeout)
        };

        Self {
            data_pressure,
            slow_timeout,
        }
    }

    fn data_pressure(&self) -> bool {
        self.data_pressure
    }

    fn slow_timeout(&self) -> Option<Duration> {
        self.slow_timeout
    }
}

struct PacketDrainCursor<T> {
    first_packet: Option<T>,
    remaining: usize,
    drained: usize,
    interleave_every: usize,
    last_interleave_at: usize,
}

impl<T> PacketDrainCursor<T> {
    fn new(first_packet: Option<T>, budget: usize, interleave_every: usize) -> Self {
        Self {
            first_packet,
            remaining: budget,
            drained: 0,
            interleave_every,
            last_interleave_at: 0,
        }
    }

    fn next(&mut self, packet_rx: &mut UnboundedReceiver<T>) -> Option<PacketDrainAction<T>> {
        if self.remaining == 0 {
            return None;
        }

        if self.interleave_due() {
            self.last_interleave_at = self.drained;
            return Some(PacketDrainAction::InterleaveFallback);
        }

        let packet = self
            .first_packet
            .take()
            .or_else(|| packet_rx.try_recv().ok())?;
        self.remaining -= 1;
        self.drained += 1;
        Some(PacketDrainAction::Packet(packet))
    }

    fn drained(&self) -> usize {
        self.drained
    }

    fn interleave_due(&self) -> bool {
        self.drained > 0
            && self.interleave_every > 0
            && self.drained.is_multiple_of(self.interleave_every)
            && self.last_interleave_at != self.drained
    }
}

struct PriorityBulkDrainCursor<T> {
    first_priority: Option<T>,
    first_bulk: Option<T>,
    remaining: usize,
    drained: usize,
}

impl<T> PriorityBulkDrainCursor<T> {
    fn new(first_priority: Option<T>, first_bulk: Option<T>, budget: usize) -> Self {
        Self {
            first_priority,
            first_bulk,
            remaining: budget,
            drained: 0,
        }
    }

    fn next(&mut self, priority_rx: &mut Receiver<T>, bulk_rx: &mut Receiver<T>) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let item = if let Some(item) = self.first_priority.take() {
            Some(item)
        } else {
            priority_rx
                .try_recv()
                .ok()
                .or_else(|| self.first_bulk.take())
                .or_else(|| bulk_rx.try_recv().ok())
        }?;

        self.remaining -= 1;
        self.drained += 1;
        Some(item)
    }

    fn drained(&self) -> usize {
        self.drained
    }

    fn charge_extra(&mut self, extra: usize) {
        self.remaining = self.remaining.saturating_sub(extra);
        self.drained = self.drained.saturating_add(extra);
    }
}

struct TunOutboundDrainCursor<T> {
    first_packet: Option<T>,
    remaining: usize,
    drained: usize,
}

impl<T> TunOutboundDrainCursor<T> {
    fn new(first_packet: Option<T>, budget: usize) -> Self {
        Self {
            first_packet,
            remaining: budget,
            drained: 0,
        }
    }

    fn next(&mut self, rx: &mut Receiver<T>) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let packet = self.first_packet.take().or_else(|| rx.try_recv().ok())?;
        self.remaining -= 1;
        self.drained += 1;
        Some(packet)
    }

    fn drained(&self) -> usize {
        self.drained
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PacketDrainAction, PacketDrainCursor, PriorityBulkDrainCursor, RxLoopDataDrainStats,
        RxLoopMaintenancePlan, RxLoopMaintenanceState, TunOutboundDrainCursor,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn rx_loop_data_drain_stats_owns_counts_total_and_pressure() {
        let empty = RxLoopDataDrainStats::default();
        assert_eq!(empty.total(), 0);
        assert!(!empty.has_drained());
        assert!(!empty.data_pressure(false));
        assert!(empty.data_pressure(true));

        let drained = RxLoopDataDrainStats::new(2, 3, 5);
        assert_eq!(drained.total(), 10);
        assert!(drained.has_drained());
        assert!(drained.data_pressure(false));
        assert!(drained.data_pressure(true));
    }

    #[test]
    fn rx_loop_maintenance_state_owns_activity_window_and_timeout_skip() {
        let start = Instant::now();
        let window = Duration::from_secs(2);
        let empty = RxLoopDataDrainStats::default();
        let drained = RxLoopDataDrainStats::new(1, 0, 0);
        let mut state = RxLoopMaintenanceState::default();

        assert!(!state.data_pressure(empty, start, window));
        assert!(!state.skip_slow_maintenance(false));

        state.record_data_activity(start);
        assert!(state.data_pressure(empty, start + Duration::from_secs(1), window));
        assert!(!state.data_pressure(empty, start + Duration::from_secs(3), window));
        assert!(state.data_pressure(drained, start + Duration::from_secs(3), window));

        state.record_maintenance_result(true, true);
        assert!(state.skip_slow_maintenance(true));
        assert!(!state.skip_slow_maintenance(false));

        state.record_maintenance_result(true, false);
        assert!(state.skip_slow_maintenance(true));

        state.record_maintenance_result(false, true);
        assert!(!state.skip_slow_maintenance(true));
    }

    #[test]
    fn rx_loop_maintenance_plan_owns_pressure_skip_and_timeout_budget() {
        let start = Instant::now();
        let window = Duration::from_secs(2);
        let idle_timeout = Duration::from_millis(100);
        let busy_timeout = Duration::from_millis(10);
        let empty = RxLoopDataDrainStats::default();
        let drained = RxLoopDataDrainStats::new(1, 0, 0);
        let mut state = RxLoopMaintenanceState::default();

        let idle = state.plan_maintenance(empty, start, window, idle_timeout, busy_timeout);
        assert_eq!(
            idle,
            RxLoopMaintenancePlan::new(false, false, idle_timeout, busy_timeout)
        );
        assert_eq!(
            RxLoopMaintenancePlan::new(false, true, idle_timeout, busy_timeout).slow_timeout(),
            Some(idle_timeout)
        );
        assert!(!idle.data_pressure());
        assert_eq!(idle.slow_timeout(), Some(idle_timeout));

        state.record_data_activity(start);
        let recent_busy = state.plan_maintenance(
            empty,
            start + Duration::from_secs(1),
            window,
            idle_timeout,
            busy_timeout,
        );
        assert!(recent_busy.data_pressure());
        assert_eq!(recent_busy.slow_timeout(), Some(busy_timeout));

        state.record_maintenance_result(true, true);
        let skipped_busy = state.plan_maintenance(
            drained,
            start + Duration::from_secs(1),
            window,
            idle_timeout,
            busy_timeout,
        );
        assert!(skipped_busy.data_pressure());
        assert_eq!(skipped_busy.slow_timeout(), None);

        let expired_idle = state.plan_maintenance(
            empty,
            start + Duration::from_secs(3),
            window,
            idle_timeout,
            busy_timeout,
        );
        assert!(!expired_idle.data_pressure());
        assert_eq!(expired_idle.slow_timeout(), Some(idle_timeout));
    }

    #[tokio::test]
    async fn endpoint_command_drain_prefers_ready_priority_over_selected_bulk() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("priority").await.unwrap();
        bulk_tx.send("bulk-queued").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("bulk-selected"), 4);

        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), Some("priority"));
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("bulk-selected")
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("bulk-queued")
        );
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn fallback_drain_prefers_ready_priority_over_selected_bulk() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("priority-fallback").await.unwrap();
        bulk_tx.send("queued-bulk-fallback").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("selected-bulk-fallback"), 4);

        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("priority-fallback")
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("selected-bulk-fallback")
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("queued-bulk-fallback")
        );
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn priority_bulk_drain_cursor_owns_selected_head_and_budget() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("queued-priority").await.unwrap();
        bulk_tx.send("queued-bulk").await.unwrap();
        let mut drain =
            PriorityBulkDrainCursor::new(Some("selected-priority"), Some("selected-bulk"), 3);

        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("selected-priority")
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("queued-priority")
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("selected-bulk")
        );
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
        assert_eq!(bulk_rx.try_recv().ok(), Some("queued-bulk"));
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn priority_bulk_drain_cursor_charges_batch_extra_against_budget() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("queued-priority").await.unwrap();
        bulk_tx.send("queued-bulk").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("selected-bulk"), 4);

        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("queued-priority")
        );
        drain.charge_extra(3);
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
        assert_eq!(bulk_rx.try_recv().ok(), Some("queued-bulk"));
        assert_eq!(drain.drained(), 4);
    }

    #[tokio::test]
    async fn packet_drain_cursor_owns_first_packet_budget_and_interleave() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        packet_tx.send("queued-3").unwrap();
        let mut drain = PacketDrainCursor::new(Some("selected"), 3, 2);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("selected"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveFallback)
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-2"))
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(packet_rx.try_recv().ok(), Some("queued-3"));
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn tun_outbound_drain_cursor_owns_first_packet_and_budget() {
        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(4);

        tun_tx.send("queued-1").await.unwrap();
        tun_tx.send("queued-2").await.unwrap();
        tun_tx.send("queued-3").await.unwrap();
        let mut drain = TunOutboundDrainCursor::new(Some("selected"), 3);

        assert_eq!(drain.next(&mut tun_rx), Some("selected"));
        assert_eq!(drain.next(&mut tun_rx), Some("queued-1"));
        assert_eq!(drain.next(&mut tun_rx), Some("queued-2"));
        assert_eq!(drain.next(&mut tun_rx), None);
        assert_eq!(tun_rx.try_recv().ok(), Some("queued-3"));
        assert_eq!(drain.drained(), 3);
    }
}
