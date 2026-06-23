//! RX event loop and packet dispatch.

use crate::control::queries;
use crate::control::{ControlMessage, ControlSenders, ControlSocket, commands};
use crate::discovery::is_punch_packet;
use crate::node::decrypt_worker::{
    DecryptFailureReport, DecryptFallback, DecryptJobBatcher, DecryptWorkerEvent,
    DecryptWorkerFallbackReceivers,
};
use crate::node::handlers::encrypted::EncryptedFrameFastPath;
use crate::node::wire::{
    COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
};
use crate::node::{
    AuthenticatedFmpPlaintext, EndpointSendBatchCommand, Node, NodeEndpointCommand, NodeError,
};
use crate::transport::PacketRx;
use crate::transport::ReceivedPacket;
use crate::upper::tun::TunOutboundRx;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;
use tracing::{debug, info, trace, warn};

mod budget;
mod drain;

#[cfg(test)]
mod tests;

use budget::*;
use drain::*;

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
        let (mut endpoint_bulk_feedback_rx, _endpoint_bulk_feedback_guard) =
            match self.endpoint_bulk_feedback_rx.take() {
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

        // Set up control socket channels. Read-only queries are separated
        // from mutating commands so operator status reads can get reserved
        // progress while a command awaits slower discovery/transport work.
        let (control_query_tx, mut control_query_rx) =
            tokio::sync::mpsc::channel::<ControlMessage>(32);
        let (control_command_tx, mut control_command_rx) =
            tokio::sync::mpsc::channel::<ControlMessage>(32);

        if self.config.node.control.enabled {
            let config = self.config.node.control.clone();
            let senders = ControlSenders::new(control_query_tx.clone(), control_command_tx.clone());
            tokio::spawn(async move {
                match ControlSocket::bind(&config) {
                    Ok(socket) => {
                        socket.accept_loop_split(senders).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to bind control socket");
                    }
                }
            });
        }
        // Drop unused sender to avoid keeping channel open if control is disabled
        drop(control_query_tx);
        drop(control_command_tx);

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
                        &mut control_query_rx,
                        &mut endpoint_bulk_feedback_rx,
                        &mut tun_outbound_rx,
                        &mut endpoint_priority_command_rx,
                        &mut endpoint_command_rx,
                        SIDE_QUEUE_INTERLEAVE_BUDGET,
                    ).await;
                    if fallback_drained > 0 || side_drained.has_data_drained() {
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
                        &mut endpoint_bulk_feedback_rx,
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
                            drained_decrypt = drained.decrypt,
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
                        RX_LOOP_SLOW_MAINTENANCE_MAX_PRESSURE_SKIPS,
                    );

                    let slow_timed_out = self.run_rx_loop_maintenance_tick(
                        maintenance_plan,
                    ).await;
                    maintenance_state.record_maintenance_result(
                        maintenance_plan,
                        slow_timed_out,
                    );

                    let post_drained = self.drain_rx_loop_data_queues(
                        &mut packet_rx,
                        &mut decrypt_fallback_rx,
                        &mut endpoint_bulk_feedback_rx,
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
                            drained_decrypt = post_drained.decrypt,
                            drained_tun = post_drained.tun,
                            drained_endpoint = post_drained.endpoint,
                            "Drained queued packets after rx-loop maintenance"
                        );
                    }
                }
                Some(event) = decrypt_fallback_rx.authenticated_bulk.recv(),
                    if authenticated_bulk_preempts_packet_rx(packet_rx.priority_ready_packets()) =>
                {
                    let fallback_drained = self.drain_decrypt_fallback(
                        &mut decrypt_fallback_rx,
                        None,
                        Some(event),
                        None,
                        NON_PACKET_DRAIN_BUDGET,
                    ).await;
                    if fallback_drained > 0 {
                        maintenance_state.record_data_activity(Instant::now());
                    }
                }
                Some(message) = control_query_rx.recv() => {
                    self.drain_control_queries(
                        &mut control_query_rx,
                        Some(message),
                        NON_PACKET_DRAIN_BUDGET,
                    ).await;
                }
                Some(feedback) = endpoint_bulk_feedback_rx.recv() => {
                    let drained = self.drain_endpoint_bulk_send_feedback(
                        &mut endpoint_bulk_feedback_rx,
                        Some(feedback),
                        NON_PACKET_DRAIN_BUDGET,
                    );
                    if drained > 0 {
                        maintenance_state.record_data_activity(Instant::now());
                    }
                }
                // Endpoint priority is app-owned latency-sensitive traffic
                // (ICMP, TCP ACK/SYN, tiny TCP data). On platforms without the
                // unix encrypt-worker fast path, this branch is the outbound
                // dataplane path, so give it an explicit turn before hot raw
                // receive. Bulk endpoint commands intentionally remain below
                // packet_rx.
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
                packet = packet_rx.recv() => {
                    match packet {
                        Some(p) => {
                            let drained = self.drain_packet_rx(
                                &mut packet_rx,
                                &mut decrypt_fallback_rx,
                                Some(RxLoopSideQueues {
                                    control_query_rx: &mut control_query_rx,
                                    endpoint_bulk_feedback_rx: &mut endpoint_bulk_feedback_rx,
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
                Some(event) = decrypt_fallback_rx.bulk.recv() => {
                    let fallback_plan = fallback_drain_plan();
                    let fallback_drained = self.drain_decrypt_fallback(
                        &mut decrypt_fallback_rx,
                        None,
                        None,
                        Some(event),
                        fallback_plan.trailing_budget,
                    ).await;
                    if fallback_drained > 0 {
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
                Some((request, response_tx)) = control_command_rx.recv() => {
                    let response = commands::dispatch(
                        self,
                        &request.command,
                        request.params.as_ref(),
                    ).await;
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
        endpoint_bulk_feedback_rx: &mut Receiver<crate::node::EndpointBulkSendFeedback>,
        tun_outbound_rx: &mut TunOutboundRx,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        budget: usize,
    ) -> RxLoopDataDrainStats {
        let drained_packets = self
            .drain_packet_rx(packet_rx, decrypt_fallback_rx, None, None, budget)
            .await;
        let non_packet_budget = non_packet_drain_budget(budget);
        let drained_decrypt = if decrypt_fallback_has_ready(decrypt_fallback_rx) {
            self.drain_decrypt_fallback(decrypt_fallback_rx, None, None, None, non_packet_budget)
                .await
        } else {
            0
        };
        let drained_endpoint_feedback = self.drain_endpoint_bulk_send_feedback(
            endpoint_bulk_feedback_rx,
            None,
            non_packet_budget,
        );
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
        RxLoopDataDrainStats::with_feedback(
            drained_packets,
            drained_decrypt,
            drained_endpoint_feedback,
            drained_tun,
            drained_endpoint,
        )
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
        let fallback_plan = fallback_drain_plan();
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
                                side_queues.control_query_rx,
                                side_queues.endpoint_bulk_feedback_rx,
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
        control_query_rx: &mut Receiver<ControlMessage>,
        endpoint_bulk_feedback_rx: &mut Receiver<crate::node::EndpointBulkSendFeedback>,
        tun_outbound_rx: &mut TunOutboundRx,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        budget: usize,
    ) -> RxLoopDataDrainStats {
        let drained_endpoint_feedback =
            self.drain_endpoint_bulk_send_feedback(endpoint_bulk_feedback_rx, None, budget);
        let feedback_remaining_budget = budget.saturating_sub(drained_endpoint_feedback);
        let control_budget = feedback_remaining_budget.min(CONTROL_QUERY_INTERLEAVE_BUDGET);
        let drained_control = self
            .drain_control_queries(control_query_rx, None, control_budget)
            .await;
        let remaining_budget = feedback_remaining_budget.saturating_sub(drained_control);
        let (endpoint_budget, tun_budget) = split_side_queue_budget(remaining_budget);
        let mut drained_endpoint = self
            .drain_endpoint_commands(
                endpoint_priority_command_rx,
                endpoint_command_rx,
                None,
                None,
                endpoint_budget,
            )
            .await;
        let mut drained_tun = self
            .drain_tun_outbound(tun_outbound_rx, None, tun_budget)
            .await;

        let endpoint_remainder = remaining_side_queue_budget(endpoint_budget, drained_endpoint);
        let tun_remainder = remaining_side_queue_budget(tun_budget, drained_tun);
        if endpoint_remainder > 0 && !tun_outbound_rx.is_empty() {
            drained_tun += self
                .drain_tun_outbound(tun_outbound_rx, None, endpoint_remainder)
                .await;
        }
        if tun_remainder > 0
            && (!endpoint_priority_command_rx.is_empty() || !endpoint_command_rx.is_empty())
        {
            drained_endpoint += self
                .drain_endpoint_commands(
                    endpoint_priority_command_rx,
                    endpoint_command_rx,
                    None,
                    None,
                    tun_remainder,
                )
                .await;
        }

        RxLoopDataDrainStats::with_control(
            0,
            drained_endpoint_feedback,
            drained_tun,
            drained_endpoint,
            drained_control,
        )
    }

    async fn drain_control_queries(
        &mut self,
        control_query_rx: &mut Receiver<ControlMessage>,
        first_message: Option<ControlMessage>,
        budget: usize,
    ) -> usize {
        let mut drain = SingleLaneDrainCursor::new(first_message, budget);
        while let Some((request, response_tx)) = drain.next(control_query_rx) {
            let response = queries::dispatch(self, &request.command, request.params.as_ref());
            let _ = response_tx.send(response);
        }

        drain.drained()
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

        drain.drained()
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
            match command.into_send_batch_oneway() {
                Ok((batch, _lane)) => {
                    let mut batch_commands = vec![batch];
                    self.coalesce_endpoint_send_batch_commands(
                        &mut drain,
                        endpoint_priority_command_rx,
                        endpoint_command_rx,
                        &mut batch_commands,
                    );
                    self.handle_endpoint_send_batch_commands(batch_commands)
                        .await;
                }
                Err(command) => {
                    self.handle_endpoint_data_command(command).await;
                }
            }
            drain.charge_extra(drain_cost.saturating_sub(1));
        }

        drain.drained()
    }

    fn drain_endpoint_bulk_send_feedback(
        &mut self,
        endpoint_bulk_feedback_rx: &mut Receiver<crate::node::EndpointBulkSendFeedback>,
        first_feedback: Option<crate::node::EndpointBulkSendFeedback>,
        budget: usize,
    ) -> usize {
        let mut drain = SingleLaneDrainCursor::new(first_feedback, budget);
        while let Some(feedback) = drain.next(endpoint_bulk_feedback_rx) {
            self.apply_endpoint_bulk_send_feedback(feedback);
        }

        drain.drained()
    }

    fn coalesce_endpoint_send_batch_commands(
        &mut self,
        drain: &mut PriorityBulkDrainCursor<NodeEndpointCommand>,
        endpoint_priority_command_rx: &mut Receiver<NodeEndpointCommand>,
        endpoint_command_rx: &mut Receiver<NodeEndpointCommand>,
        batch_commands: &mut Vec<EndpointSendBatchCommand>,
    ) {
        let mut payloads = batch_commands
            .iter()
            .fold(0usize, |total, command| total.saturating_add(command.len()));
        while payloads < ENDPOINT_COMMAND_COALESCE_MAX_PACKETS {
            let Some(command) =
                drain.next_bulk_if_no_priority(endpoint_priority_command_rx, endpoint_command_rx)
            else {
                break;
            };
            let drain_cost = command.drain_cost();
            match command.into_send_batch_oneway() {
                Ok((batch, _lane))
                    if batch_commands.last().is_some_and(|last| {
                        last.can_coalesce_with(&batch, ENDPOINT_COMMAND_COALESCE_MAX_PACKETS)
                    }) =>
                {
                    payloads = payloads.saturating_add(batch.len());
                    batch_commands.push(batch);
                    drain.charge_extra(drain_cost.saturating_sub(1));
                }
                Ok((batch, lane)) => {
                    drain.defer_bulk(NodeEndpointCommand::SendBatchOneway {
                        command: batch,
                        lane,
                    });
                    break;
                }
                Err(command) => {
                    drain.defer_bulk(command);
                    break;
                }
            }
        }
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
            DecryptWorkerEvent::AuthenticatedFmpReceive(receive) => {
                self.process_authenticated_fmp_receive_from_worker(receive);
            }
            DecryptWorkerEvent::AuthenticatedSession(session) => {
                self.process_authenticated_session_from_worker(session)
                    .await;
            }
            DecryptWorkerEvent::AuthenticatedSessionBatch(sessions) => {
                self.process_authenticated_session_batch_from_worker(sessions)
                    .await;
            }
            DecryptWorkerEvent::DirectSessionCommit(commit) => {
                self.process_direct_session_commit_from_worker(commit).await;
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(commits) => {
                self.process_direct_session_commit_batch_from_worker(commits)
                    .await;
            }
            DecryptWorkerEvent::DirectSessionData(direct) => {
                self.process_direct_session_data_from_worker(direct).await;
            }
            DecryptWorkerEvent::DirectSessionDataBatch(directs) => {
                self.process_direct_session_data_batch_from_worker(directs)
                    .await;
            }
            DecryptWorkerEvent::FspDecryptFailure(report) => {
                self.process_fsp_decrypt_failure_from_worker(report).await;
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
        first_authenticated_bulk_event: Option<DecryptWorkerEvent>,
        first_bulk_event: Option<DecryptWorkerEvent>,
        budget: usize,
    ) -> usize {
        self.begin_endpoint_event_batch();
        let mut drain = DecryptReturnDrainCursor::new(
            first_priority_event,
            first_authenticated_bulk_event,
            first_bulk_event,
            budget,
        );
        while let Some(event) =
            drain.next(&mut rx.priority, &mut rx.authenticated_bulk, &mut rx.bulk)
        {
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
