//! RX event loop and packet dispatch.

use crate::control::queries;
use crate::control::{ControlSocket, commands};
use crate::discovery::is_punch_packet;
use crate::node::decrypt_worker::{
    DecryptFailureReport, DecryptFallback, DecryptJob, DecryptJobBatcher, DecryptWorkerEvent,
    DecryptWorkerFallbackReceivers,
};
use crate::node::handlers::encrypted::EncryptedFrameFastPath;
use crate::node::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use crate::node::{AuthenticatedFmpPlaintext, Node, NodeEndpointCommand, NodeError};
use crate::transport::PacketRx;
use crate::transport::ReceivedPacket;
use crate::upper::tun::TunOutboundRx;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;
use tracing::{debug, info, trace, warn};

/// How often the raw-packet drain loop yields a slice of work to the
/// decrypt-fallback drain. Keeps TCP ACK / heartbeat / handshake
/// progress steady under sustained inbound bursts.
const FALLBACK_INTERLEAVE_EVERY: usize = 32;
/// Cap on the per-interleave fallback drain so a hot inbound spike
/// can't starve the outer raw-packet drain in the opposite direction.
const FALLBACK_INTERLEAVE_BUDGET: usize = 64;
/// Once decrypt completions are already queued at this scale, continuing to
/// feed more bulk ciphertext into workers before draining plaintext adds
/// latency without improving liveness. The pressure path is gated off whenever
/// raw priority packets are queued.
const FALLBACK_PRESSURE_HIGH_WATER: usize = 1024;
const FALLBACK_PRESSURE_INTERLEAVE_EVERY: usize = 16;
const FALLBACK_PRESSURE_INTERLEAVE_BUDGET: usize = 128;
const FALLBACK_PRESSURE_TRAILING_BUDGET: usize = 128;
/// How often a hot inbound packet drain gives outbound side queues a bounded
/// turn. This keeps TUN egress and endpoint control sends moving when
/// `packet_rx` remains ready for many consecutive biased select iterations.
const SIDE_QUEUE_INTERLEAVE_EVERY: usize = 64;
/// Side-queue interleaves are a progress reserve, not a full drain. Keeping
/// this smaller than the packet budget preserves raw receive throughput while
/// avoiding tick-sized liveness stalls.
const SIDE_QUEUE_INTERLEAVE_BUDGET: usize = 64;
/// Top-level non-packet queues get shorter turns than raw packet receive.
/// Returning to the biased select loop after a small slice lets ready
/// `packet_rx` preempt bulk fallback, TUN egress, and endpoint command work
/// without adding a second packet-drain path inside those handlers.
const NON_PACKET_DRAIN_BUDGET: usize = 64;
/// Raw receive burst cap. This amortizes select/scheduler hops across a hot
/// transport queue; fallback/side interleaves reserve progress before the cap.
const PACKET_DRAIN_BUDGET: usize = 512;
const RX_LOOP_SLOW_MAINTENANCE_IDLE_TIMEOUT: Duration = Duration::from_millis(100);
const RX_LOOP_SLOW_MAINTENANCE_BUSY_TIMEOUT: Duration = Duration::from_millis(10);
const RX_LOOP_RECENT_DATA_ACTIVITY_WINDOW: Duration = Duration::from_secs(2);
const RX_LOOP_FAULT_MAX_DELAY_MS: u64 = 5_000;

fn non_packet_drain_budget(packet_budget: usize) -> usize {
    packet_budget.min(NON_PACKET_DRAIN_BUDGET)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FallbackDrainPlan {
    interleave_every: usize,
    interleave_budget: usize,
    trailing_budget: usize,
}

impl FallbackDrainPlan {
    const fn normal() -> Self {
        Self {
            interleave_every: FALLBACK_INTERLEAVE_EVERY,
            interleave_budget: FALLBACK_INTERLEAVE_BUDGET,
            trailing_budget: NON_PACKET_DRAIN_BUDGET,
        }
    }

    const fn pressured() -> Self {
        Self {
            interleave_every: FALLBACK_PRESSURE_INTERLEAVE_EVERY,
            interleave_budget: FALLBACK_PRESSURE_INTERLEAVE_BUDGET,
            trailing_budget: FALLBACK_PRESSURE_TRAILING_BUDGET,
        }
    }
}

fn fallback_drain_plan(
    transport_priority_packets: usize,
    decrypt_fallback_bulk_packets: usize,
) -> FallbackDrainPlan {
    if transport_priority_packets == 0
        && decrypt_fallback_bulk_packets >= FALLBACK_PRESSURE_HIGH_WATER
    {
        FallbackDrainPlan::pressured()
    } else {
        FallbackDrainPlan::normal()
    }
}

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
        // Tokio intervals tick immediately on first poll. Consume that startup
        // tick so the reserved-progress branch below represents a due periodic
        // maintenance turn, not an eager pre-data maintenance pass.
        tick.tick().await;

        loop {
            tokio::select! {
                biased;
                // Priority decrypt-worker fallback drains first. The
                // previous packet-first ordering could hold small ACK,
                // heartbeat, and failure-report plaintexts behind a hot
                // raw-packet drain long enough to collapse TCP. Bulk
                // fallback is intentionally below `packet_rx`: bulk
                // plaintext must keep making bounded progress, but it
                // should not stop fresh transport priority packets from
                // being dequeued. `drain_packet_rx` interleaves fallback
                // turns every few dozen packets to keep that progress
                // reserve while avoiding a bulk-fallback convoy.
                Some(event) = decrypt_fallback_rx.priority.recv() => {
                    let fallback_drained = self.drain_decrypt_priority_fallback(
                        &mut decrypt_fallback_rx.priority,
                        Some(event),
                        PACKET_DRAIN_BUDGET,
                    ).await;
                    let side_drained = self.drain_rx_loop_side_queues(
                        &mut tun_outbound_rx,
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        SIDE_QUEUE_INTERLEAVE_BUDGET,
                    ).await;
                    if fallback_drained > 0 || side_drained.has_drained() {
                        maintenance_state.record_data_activity(Instant::now());
                    }
                }
                // Timer-driven liveness is a reserved-progress branch. It
                // performs bounded pre/post data drains and timeboxes slow
                // discovery/status work, so hot packet or bulk-fallback
                // queues cannot indefinitely postpone heartbeat, rekey, MMP,
                // route aging, or path maintenance.
                _ = tick.tick() => {
                    let drained = self.drain_rx_loop_data_queues(
                        &mut packet_rx,
                        &mut decrypt_fallback_rx,
                        &mut tun_outbound_rx,
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        NON_PACKET_DRAIN_BUDGET,
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
                packet = packet_rx.recv() => {
                    match packet {
                        Some(p) => {
                            let drained = self.drain_packet_rx(
                                &mut packet_rx,
                                &mut decrypt_fallback_rx,
                                Some(RxLoopSideQueues {
                                    tun_outbound_rx: &mut tun_outbound_rx,
                                    endpoint_priority_command_rx: &mut endpoint_priority_command_rx,
                                    endpoint_command_rx: &mut endpoint_command_rx,
                                }),
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
                Some(command) = endpoint_priority_command_rx.recv() => {
                    let drained = self.drain_endpoint_commands(
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        Some(command),
                        None,
                        NON_PACKET_DRAIN_BUDGET,
                    ).await;
                    if drained > 0 {
                        maintenance_state.record_data_activity(Instant::now());
                    }
                }
                Some(event) = decrypt_fallback_rx.bulk.recv() => {
                    let fallback_plan = fallback_drain_plan(
                        packet_rx.priority_queued_packets(),
                        decrypt_fallback_rx.bulk_queued_packets(),
                    );
                    let fallback_drained = self.drain_decrypt_fallback(
                        &mut decrypt_fallback_rx,
                        None,
                        Some(event),
                        fallback_plan.trailing_budget,
                    ).await;
                    let side_drained = self.drain_rx_loop_side_queues(
                        &mut tun_outbound_rx,
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        SIDE_QUEUE_INTERLEAVE_BUDGET,
                    ).await;
                    if fallback_drained > 0 || side_drained.has_drained() {
                        maintenance_state.record_data_activity(Instant::now());
                    }
                }
                Some(ipv6_packet) = tun_outbound_rx.recv() => {
                    let drained = self.drain_tun_outbound(
                        &mut tun_outbound_rx,
                        Some(ipv6_packet),
                        NON_PACKET_DRAIN_BUDGET,
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
                Some(command) = endpoint_command_rx.recv() => {
                    let drained = self.drain_endpoint_commands(
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        None,
                        Some(command),
                        NON_PACKET_DRAIN_BUDGET,
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
        packet_rx: &mut PacketRx,
        decrypt_fallback_rx: &mut DecryptWorkerFallbackReceivers,
        tun_outbound_rx: &mut TunOutboundRx,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        budget: usize,
    ) -> RxLoopDataDrainStats {
        let drained_packets = self
            .drain_packet_rx(packet_rx, decrypt_fallback_rx, None, None, budget)
            .await;
        let non_packet_budget = non_packet_drain_budget(budget);
        let drained_tun = self
            .drain_tun_outbound(tun_outbound_rx, None, non_packet_budget)
            .await;
        let drained_endpoint = self
            .drain_endpoint_commands(
                endpoint_priority_command_rx,
                endpoint_command_rx,
                None,
                None,
                non_packet_budget,
            )
            .await;
        RxLoopDataDrainStats::new(drained_packets, drained_tun, drained_endpoint)
    }

    async fn drain_packet_rx(
        &mut self,
        packet_rx: &mut PacketRx,
        decrypt_fallback_rx: &mut DecryptWorkerFallbackReceivers,
        mut side_queues: Option<RxLoopSideQueues<'_>>,
        first_packet: Option<ReceivedPacket>,
        budget: usize,
    ) -> usize {
        // Drain remaining ready inbound packets in a tight loop before
        // yielding back to select! Every yield is a scheduler hop, and at
        // line rate transports typically have several packets available per
        // wake. Caps at a batch boundary so other branches eventually get a
        // turn even under sustained load.
        self.begin_endpoint_event_batch();
        let side_queue_interleave_every = if side_queues.is_some() {
            SIDE_QUEUE_INTERLEAVE_EVERY
        } else {
            0
        };
        let fallback_plan = fallback_drain_plan(
            packet_rx.priority_queued_packets(),
            decrypt_fallback_rx.bulk_queued_packets(),
        );
        let mut drain = PacketDrainCursor::new(
            first_packet,
            budget,
            fallback_plan.interleave_every,
            side_queue_interleave_every,
        );
        let mut decrypt_jobs = DecryptJobBatcher::new();
        while let Some(action) = drain.next(packet_rx) {
            match action {
                PacketDrainAction::Packet(packet) => {
                    let action = self.begin_process_packet(packet);
                    match action {
                        PacketProcessAction::DecryptJob { job } => {
                            if let Some(workers) = self.decrypt_workers.as_ref() {
                                decrypt_jobs.push(workers, job);
                            }
                        }
                        PacketProcessAction::Done => {}
                        action => {
                            self.flush_decrypt_job_batcher(&mut decrypt_jobs);
                            self.finish_packet_process(action).await;
                        }
                    }
                }
                PacketDrainAction::InterleaveFallback => {
                    self.flush_decrypt_job_batcher(&mut decrypt_jobs);
                    let drained = if decrypt_fallback_has_ready(decrypt_fallback_rx) {
                        self.drain_decrypt_fallback(
                            decrypt_fallback_rx,
                            None,
                            None,
                            fallback_plan.interleave_budget,
                        )
                        .await
                    } else {
                        0
                    };
                    if drained == 0 {
                        drain.refund_empty_interleave_turn();
                    }
                }
                PacketDrainAction::InterleaveSideQueues => {
                    self.flush_decrypt_job_batcher(&mut decrypt_jobs);
                    let drained = if let Some(side_queues) = side_queues.as_mut() {
                        if rx_loop_side_queues_have_ready(side_queues) {
                            self.drain_rx_loop_side_queues(
                                side_queues.tun_outbound_rx,
                                side_queues.endpoint_priority_command_rx,
                                side_queues.endpoint_command_rx,
                                SIDE_QUEUE_INTERLEAVE_BUDGET,
                            )
                            .await
                        } else {
                            RxLoopDataDrainStats::default()
                        }
                    } else {
                        RxLoopDataDrainStats::default()
                    };
                    if !drained.has_drained() {
                        drain.refund_empty_interleave_turn();
                    }
                }
            }
        }

        self.flush_decrypt_job_batcher(&mut decrypt_jobs);
        let drained = drain.drained();
        if drained > 0 {
            // One trailing fallback slice so the last bounced packets of the
            // burst aren't held up by the post-burst send flush. Keep it a
            // non-packet turn: bulk fallback should not convoy ahead of fresh
            // transport receive work after every hot packet drain.
            self.drain_decrypt_fallback(
                decrypt_fallback_rx,
                None,
                None,
                fallback_plan.trailing_budget.min(budget),
            )
            .await;
            self.finish_endpoint_event_batch();
        } else {
            self.finish_endpoint_event_batch();
        }
        drained
    }

    async fn drain_rx_loop_side_queues(
        &mut self,
        tun_outbound_rx: &mut TunOutboundRx,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        budget: usize,
    ) -> RxLoopDataDrainStats {
        let endpoint_budget = (budget / 2).max(1);
        let tun_budget = budget.saturating_sub(endpoint_budget).max(1);
        let drained_endpoint = self
            .drain_endpoint_commands(
                endpoint_priority_command_rx,
                endpoint_command_rx,
                None,
                None,
                endpoint_budget,
            )
            .await;
        let drained_tun = self
            .drain_tun_outbound(tun_outbound_rx, None, tun_budget)
            .await;
        RxLoopDataDrainStats::new(0, drained_tun, drained_endpoint)
    }

    async fn drain_tun_outbound(
        &mut self,
        tun_outbound_rx: &mut TunOutboundRx,
        first_packet: Option<Vec<u8>>,
        budget: usize,
    ) -> usize {
        let mut drain = SingleLaneDrainCursor::new(first_packet, budget);
        while let Some(packet) = drain.next(tun_outbound_rx) {
            self.handle_tun_outbound(packet).await;
        }

        let drained = drain.drained();
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
            crate::perf_profile::record_event(
                crate::perf_profile::Event::RxLoopSlowMaintenanceSkipped,
            );
            return false;
        };

        if tokio::time::timeout(slow_timeout, self.run_rx_loop_slow_maintenance_tick())
            .await
            .is_err()
        {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::RxLoopSlowMaintenanceTimeout,
            );
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
    /// processor as one authenticated receive envelope. The envelope keeps the
    /// worker-captured source peer, FMP flags, packet facts, and plaintext slice
    /// together so peer bookkeeping and link dispatch cannot drift apart.
    async fn process_decrypt_worker_event(&mut self, event: DecryptWorkerEvent) {
        event.record_queue_wait();
        match event {
            DecryptWorkerEvent::Plaintext(fallback) => {
                self.process_decrypt_fallback(fallback).await;
            }
            DecryptWorkerEvent::PlaintextBatch(fallbacks) => {
                for fallback in fallbacks {
                    self.process_decrypt_fallback(fallback).await;
                }
            }
            DecryptWorkerEvent::DecryptFailure(report) => {
                self.process_decrypt_failure_report(report).await;
            }
        }
    }

    async fn process_decrypt_fallback(&mut self, fallback: DecryptFallback) {
        let plaintext = &fallback.packet_data[fallback.fmp_plaintext_offset
            ..fallback.fmp_plaintext_offset + fallback.fmp_plaintext_len];
        self.process_authentic_fmp_plaintext(AuthenticatedFmpPlaintext::new(
            fallback.source_peer,
            fallback.transport_id,
            &fallback.remote_addr,
            fallback.timestamp_ms,
            fallback.packet_len,
            fallback.fmp_counter,
            fallback.fmp_flags,
            plaintext,
        ))
        .await;
    }

    async fn process_decrypt_failure_report(&mut self, report: DecryptFailureReport) {
        debug!(
            peer = %self.peer_display_name(report.source_peer.node_addr()),
            counter = report.fmp_counter,
            replay_highest = report.fmp_replay_highest,
            "Worker FMP AEAD decryption failed"
        );
        self.handle_decrypt_failure_report(&report).await;
    }

    /// Drain only the priority decrypt-worker fallback lane.
    ///
    /// This is the top-level reserved-progress arm: priority plaintext and
    /// decrypt failures get first service, but bulk fallback stays behind
    /// `packet_rx` unless it is explicitly interleaved inside a packet drain
    /// or selected by its own lower-priority branch.
    async fn drain_decrypt_priority_fallback(
        &mut self,
        priority_rx: &mut Receiver<DecryptWorkerEvent>,
        first_event: Option<DecryptWorkerEvent>,
        budget: usize,
    ) -> usize {
        self.begin_endpoint_event_batch();
        let mut drain = SingleLaneDrainCursor::new(first_event, budget);
        while let Some(event) = drain.next(priority_rx) {
            self.process_decrypt_worker_event(event).await;
        }
        let drained = drain.drained();
        self.finish_endpoint_event_batch();
        drained
    }

    /// Drain up to `budget` queued fallbacks without yielding back to
    /// `select!`. Returns the number processed. Called both from the
    /// bulk-fallback select arm (after the selected head item) and interleaved
    /// inside the packet_rx drain loop so bounced FMP plaintexts can't
    /// accumulate behind a hot inbound packet turn.
    async fn drain_decrypt_fallback(
        &mut self,
        rx: &mut DecryptWorkerFallbackReceivers,
        first_priority_event: Option<DecryptWorkerEvent>,
        first_bulk_event: Option<DecryptWorkerEvent>,
        budget: usize,
    ) -> usize {
        self.begin_endpoint_event_batch();
        let mut drain =
            PriorityBulkDrainCursor::new(first_priority_event, first_bulk_event, budget);
        while let Some(event) = drain.next(&mut rx.priority, &mut rx.bulk) {
            rx.release_dequeued_event(&event);
            let extra = event.packet_count().saturating_sub(1);
            self.process_decrypt_worker_event(event).await;
            drain.charge_extra(extra);
        }
        let drained = drain.drained();
        self.finish_endpoint_event_batch();
        drained
    }

    /// Process a single received packet.
    ///
    /// Dispatches based on the phase field in the 4-byte common prefix.
    #[cfg(test)]
    pub(in crate::node) async fn process_packet(&mut self, packet: ReceivedPacket) {
        let action = self.begin_process_packet(packet);
        self.finish_packet_process(action).await;
    }

    fn begin_process_packet(&mut self, packet: ReceivedPacket) -> PacketProcessAction {
        let timer = crate::perf_profile::Timer::start(crate::perf_profile::Stage::ProcessPacket);
        let priority_sized = packet.is_priority_sized();
        let priority_count = u64::from(priority_sized);
        let bulk_count = u64::from(!priority_sized);
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::TransportQueueWait,
            crate::perf_profile::Stage::TransportPriorityQueueWait,
            crate::perf_profile::Stage::TransportBulkQueueWait,
            packet.trace_enqueued_at,
            1,
            priority_count,
            bulk_count,
        );
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::TransportRxLoopWait,
            crate::perf_profile::Stage::TransportPriorityRxLoopWait,
            crate::perf_profile::Stage::TransportBulkRxLoopWait,
            packet.trace_rx_loop_owned_at,
            1,
            priority_count,
            bulk_count,
        );
        if is_punch_packet(&packet.data) {
            trace!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                bytes = packet.data.len(),
                "Dropping stray punch probe/ack in FMP rx loop"
            );
            return PacketProcessAction::Done;
        }
        if packet.data.len() < COMMON_PREFIX_SIZE {
            return PacketProcessAction::Done; // Drop packets too short for common prefix
        }

        let prefix = match CommonPrefix::parse(&packet.data) {
            Some(p) => p,
            None => return PacketProcessAction::Done, // Malformed prefix
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
            return PacketProcessAction::Done;
        }

        match prefix.phase {
            PHASE_ESTABLISHED => match self.try_prepare_encrypted_frame_for_worker(packet) {
                EncryptedFrameFastPath::Dispatch(job) => PacketProcessAction::DecryptJob { job },
                EncryptedFrameFastPath::Dropped => PacketProcessAction::Done,
                EncryptedFrameFastPath::Slow(packet) => {
                    PacketProcessAction::EncryptedSlow { packet, timer }
                }
            },
            PHASE_MSG1 => PacketProcessAction::Msg1 { packet, timer },
            PHASE_MSG2 => PacketProcessAction::Msg2 { packet, timer },
            _ => {
                debug!(
                    phase = prefix.phase,
                    transport_id = %packet.transport_id,
                    "Unknown FMP phase, dropping"
                );
                PacketProcessAction::Done
            }
        }
    }

    async fn finish_packet_process(&mut self, action: PacketProcessAction) {
        match action {
            PacketProcessAction::Done => {}
            PacketProcessAction::DecryptJob { job } => {
                if let Some(workers) = self.decrypt_workers.as_ref() {
                    workers.dispatch_job(job);
                }
            }
            PacketProcessAction::EncryptedSlow {
                packet,
                timer: _timer,
            } => {
                self.handle_encrypted_frame_slow(packet).await;
            }
            PacketProcessAction::Msg1 {
                packet,
                timer: _timer,
            } => {
                self.handle_msg1(packet).await;
            }
            PacketProcessAction::Msg2 {
                packet,
                timer: _timer,
            } => {
                self.handle_msg2(packet).await;
            }
        }
    }

    fn flush_decrypt_job_batcher(&self, batcher: &mut DecryptJobBatcher) {
        if let Some(workers) = self.decrypt_workers.as_ref() {
            batcher.flush(workers);
        }
    }
}

enum PacketProcessAction {
    Done,
    DecryptJob {
        job: DecryptJob,
    },
    EncryptedSlow {
        packet: ReceivedPacket,
        timer: crate::perf_profile::Timer,
    },
    Msg1 {
        packet: ReceivedPacket,
        timer: crate::perf_profile::Timer,
    },
    Msg2 {
        packet: ReceivedPacket,
        timer: crate::perf_profile::Timer,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum PacketDrainAction<T> {
    Packet(T),
    InterleaveFallback,
    InterleaveSideQueues,
}

struct RxLoopSideQueues<'a> {
    tun_outbound_rx: &'a mut TunOutboundRx,
    endpoint_priority_command_rx: &'a mut Receiver<NodeEndpointCommand>,
    endpoint_command_rx: &'a mut Receiver<NodeEndpointCommand>,
}

fn decrypt_fallback_has_ready(rx: &DecryptWorkerFallbackReceivers) -> bool {
    !rx.priority.is_empty() || !rx.bulk.is_empty()
}

fn rx_loop_side_queues_have_ready(side_queues: &RxLoopSideQueues<'_>) -> bool {
    !side_queues.tun_outbound_rx.is_empty()
        || !side_queues.endpoint_priority_command_rx.is_empty()
        || !side_queues.endpoint_command_rx.is_empty()
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
    fallback_interleave_every: usize,
    side_queue_interleave_every: usize,
    packets_until_fallback_interleave: usize,
    packets_until_side_queue_interleave: usize,
}

impl<T> PacketDrainCursor<T> {
    fn new(
        first_packet: Option<T>,
        budget: usize,
        fallback_interleave_every: usize,
        side_queue_interleave_every: usize,
    ) -> Self {
        Self {
            first_packet,
            remaining: budget,
            drained: 0,
            fallback_interleave_every,
            side_queue_interleave_every,
            packets_until_fallback_interleave: fallback_interleave_every,
            packets_until_side_queue_interleave: side_queue_interleave_every,
        }
    }

    fn next<R>(&mut self, packet_rx: &mut R) -> Option<PacketDrainAction<T>>
    where
        R: PacketDrainReceiver<T>,
    {
        if self.remaining == 0 {
            return None;
        }

        if self.fallback_interleave_due() {
            self.packets_until_fallback_interleave = self.fallback_interleave_every;
            self.charge_interleave_turn();
            return Some(PacketDrainAction::InterleaveFallback);
        }

        if self.side_queue_interleave_due() {
            self.packets_until_side_queue_interleave = self.side_queue_interleave_every;
            self.charge_interleave_turn();
            return Some(PacketDrainAction::InterleaveSideQueues);
        }

        let packet = self
            .first_packet
            .take()
            .or_else(|| packet_rx.try_recv_packet())?;
        self.charge_packet();
        Some(PacketDrainAction::Packet(packet))
    }

    fn drained(&self) -> usize {
        self.drained
    }

    fn fallback_interleave_due(&self) -> bool {
        self.drained > 0
            && self.fallback_interleave_every > 0
            && self.packets_until_fallback_interleave == 0
    }

    fn side_queue_interleave_due(&self) -> bool {
        self.drained > 0
            && self.side_queue_interleave_every > 0
            && self.packets_until_side_queue_interleave == 0
    }

    fn charge_packet(&mut self) {
        self.remaining -= 1;
        self.drained += 1;
        if self.packets_until_fallback_interleave > 0 {
            self.packets_until_fallback_interleave -= 1;
        }
        if self.packets_until_side_queue_interleave > 0 {
            self.packets_until_side_queue_interleave -= 1;
        }
    }

    fn charge_interleave_turn(&mut self) {
        self.remaining -= 1;
    }

    fn refund_empty_interleave_turn(&mut self) {
        self.remaining += 1;
    }
}

trait PacketDrainReceiver<T> {
    fn try_recv_packet(&mut self) -> Option<T>;
}

impl<T> PacketDrainReceiver<T> for tokio::sync::mpsc::UnboundedReceiver<T> {
    fn try_recv_packet(&mut self) -> Option<T> {
        self.try_recv().ok()
    }
}

impl PacketDrainReceiver<ReceivedPacket> for PacketRx {
    fn try_recv_packet(&mut self) -> Option<ReceivedPacket> {
        self.try_recv().ok()
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

struct SingleLaneDrainCursor<T> {
    first_item: Option<T>,
    remaining: usize,
    drained: usize,
}

impl<T> SingleLaneDrainCursor<T> {
    fn new(first_item: Option<T>, budget: usize) -> Self {
        Self {
            first_item,
            remaining: budget,
            drained: 0,
        }
    }

    fn next(&mut self, rx: &mut Receiver<T>) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let packet = self.first_item.take().or_else(|| rx.try_recv().ok())?;
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
        FALLBACK_INTERLEAVE_BUDGET, FALLBACK_INTERLEAVE_EVERY, FALLBACK_PRESSURE_HIGH_WATER,
        FALLBACK_PRESSURE_INTERLEAVE_BUDGET, FALLBACK_PRESSURE_INTERLEAVE_EVERY,
        FALLBACK_PRESSURE_TRAILING_BUDGET, FallbackDrainPlan, NON_PACKET_DRAIN_BUDGET,
        PACKET_DRAIN_BUDGET, PacketDrainAction, PacketDrainCursor, PriorityBulkDrainCursor,
        RxLoopDataDrainStats, RxLoopMaintenancePlan, RxLoopMaintenanceState, SingleLaneDrainCursor,
        fallback_drain_plan, non_packet_drain_budget,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn non_packet_drain_budget_caps_large_packet_turns() {
        assert_eq!(non_packet_drain_budget(0), 0);
        assert_eq!(non_packet_drain_budget(8), 8);
        assert_eq!(
            non_packet_drain_budget(PACKET_DRAIN_BUDGET),
            NON_PACKET_DRAIN_BUDGET
        );
    }

    #[test]
    fn fallback_drain_plan_expands_bulk_turns_only_without_transport_priority() {
        assert_eq!(
            fallback_drain_plan(0, FALLBACK_PRESSURE_HIGH_WATER),
            FallbackDrainPlan {
                interleave_every: FALLBACK_PRESSURE_INTERLEAVE_EVERY,
                interleave_budget: FALLBACK_PRESSURE_INTERLEAVE_BUDGET,
                trailing_budget: FALLBACK_PRESSURE_TRAILING_BUDGET,
            }
        );
        assert_eq!(
            fallback_drain_plan(0, FALLBACK_PRESSURE_HIGH_WATER - 1),
            FallbackDrainPlan {
                interleave_every: FALLBACK_INTERLEAVE_EVERY,
                interleave_budget: FALLBACK_INTERLEAVE_BUDGET,
                trailing_budget: NON_PACKET_DRAIN_BUDGET,
            }
        );
        assert_eq!(
            fallback_drain_plan(1, FALLBACK_PRESSURE_HIGH_WATER),
            FallbackDrainPlan {
                interleave_every: FALLBACK_INTERLEAVE_EVERY,
                interleave_budget: FALLBACK_INTERLEAVE_BUDGET,
                trailing_budget: NON_PACKET_DRAIN_BUDGET,
            },
            "fresh transport priority packets must keep the normal bulk-fallback cadence"
        );
    }

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
    async fn priority_fallback_drain_leaves_bulk_for_lower_priority_turn() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("queued-priority").await.unwrap();
        bulk_tx.send("queued-bulk").await.unwrap();
        let mut drain = SingleLaneDrainCursor::new(Some("selected-priority"), 4);

        assert_eq!(drain.next(&mut priority_rx), Some("selected-priority"));
        assert_eq!(drain.next(&mut priority_rx), Some("queued-priority"));
        assert_eq!(drain.next(&mut priority_rx), None);
        assert_eq!(bulk_rx.try_recv().ok(), Some("queued-bulk"));
        assert_eq!(drain.drained(), 2);
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
        let mut drain = PacketDrainCursor::new(Some("selected"), 3, 2, 0);

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
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(packet_rx.try_recv().ok(), Some("queued-2"));
        assert_eq!(drain.drained(), 2);
    }

    #[tokio::test]
    async fn packet_drain_cursor_charges_interleaves_against_budget() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        let mut drain = PacketDrainCursor::new(Some("selected"), 4, 2, 0);

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
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn packet_drain_cursor_refunds_empty_interleave_turns() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        packet_tx.send("queued-3").unwrap();
        let mut drain = PacketDrainCursor::new(None, 3, 1, 0);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveFallback)
        );
        drain.refund_empty_interleave_turn();
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-2"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveFallback)
        );
        drain.refund_empty_interleave_turn();
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-3"))
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn packet_drain_cursor_interleaves_side_queues_after_fallback() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        packet_tx.send("queued-3").unwrap();
        let mut drain = PacketDrainCursor::new(None, 5, 2, 2);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-2"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveFallback)
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::InterleaveSideQueues)
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-3"))
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn packet_drain_cursor_can_disable_side_queue_interleaves() {
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

        packet_tx.send("queued-1").unwrap();
        packet_tx.send("queued-2").unwrap();
        packet_tx.send("queued-3").unwrap();
        let mut drain = PacketDrainCursor::new(None, 3, 0, 0);

        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-1"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-2"))
        );
        assert_eq!(
            drain.next(&mut packet_rx),
            Some(PacketDrainAction::Packet("queued-3"))
        );
        assert_eq!(drain.next(&mut packet_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn single_lane_drain_cursor_owns_first_item_and_budget() {
        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(4);

        tun_tx.send("queued-1").await.unwrap();
        tun_tx.send("queued-2").await.unwrap();
        tun_tx.send("queued-3").await.unwrap();
        let mut drain = SingleLaneDrainCursor::new(Some("selected"), 3);

        assert_eq!(drain.next(&mut tun_rx), Some("selected"));
        assert_eq!(drain.next(&mut tun_rx), Some("queued-1"));
        assert_eq!(drain.next(&mut tun_rx), Some("queued-2"));
        assert_eq!(drain.next(&mut tun_rx), None);
        assert_eq!(tun_rx.try_recv().ok(), Some("queued-3"));
        assert_eq!(drain.drained(), 3);
    }
}
