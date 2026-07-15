//! RX event loop and dataplane dispatch.

use crate::control::queries;
use crate::control::{ControlMessage, ControlSenders, ControlSocket, commands};
use crate::dataplane::DataplaneFastIngressRx;
use crate::node::{
    EndpointDataBatchRx, EndpointEventSender, Node, NodeError, endpoint_data_batch_channel,
};
use crate::transport::PacketRx;
use crate::upper::tun::TunOutboundRx;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Receiver;
use tracing::{debug, info, warn};

mod budget;
mod dataplane;
mod drain;

#[cfg(test)]
mod tests;

use budget::*;
use drain::*;

pub(in crate::node) struct RxLoopDataplaneIo<'a> {
    packet_rx: &'a mut PacketRx,
    dataplane_fast_ingress_rx: &'a mut DataplaneFastIngressRx,
    endpoint_data_rx: &'a mut EndpointDataBatchRx,
    tun_outbound_rx: &'a mut TunOutboundRx,
    endpoint_tx: &'a EndpointEventSender,
}

struct RxLoopDataplaneRuntime {
    packet_rx: PacketRx,
    dataplane_fast_ingress_rx: DataplaneFastIngressRx,
    endpoint_data_rx: EndpointDataBatchRx,
    tun_outbound_rx: TunOutboundRx,
    endpoint_tx: EndpointEventSender,
}

impl RxLoopDataplaneRuntime {
    fn io(&mut self) -> RxLoopDataplaneIo<'_> {
        RxLoopDataplaneIo {
            packet_rx: &mut self.packet_rx,
            dataplane_fast_ingress_rx: &mut self.dataplane_fast_ingress_rx,
            endpoint_data_rx: &mut self.endpoint_data_rx,
            tun_outbound_rx: &mut self.tun_outbound_rx,
            endpoint_tx: &self.endpoint_tx,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::node) struct RxLoopDataplaneTurnLimits {
    packet: usize,
    endpoint: usize,
    tun: usize,
    crypto: usize,
}

impl RxLoopDataplaneTurnLimits {
    pub(in crate::node) fn new(packet: usize, endpoint: usize, tun: usize, crypto: usize) -> Self {
        Self {
            packet,
            endpoint,
            tun,
            crypto,
        }
    }
}

#[cfg(test)]
pub(in crate::node) fn rx_loop_dataplane_io<'a>(
    packet_rx: &'a mut PacketRx,
    dataplane_fast_ingress_rx: &'a mut DataplaneFastIngressRx,
    endpoint_data_rx: &'a mut EndpointDataBatchRx,
    tun_outbound_rx: &'a mut TunOutboundRx,
    endpoint_tx: &'a EndpointEventSender,
) -> RxLoopDataplaneIo<'a> {
    RxLoopDataplaneIo {
        packet_rx,
        dataplane_fast_ingress_rx,
        endpoint_data_rx,
        tun_outbound_rx,
        endpoint_tx,
    }
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
        let packet_rx = self.packet_rx.take().ok_or(NodeError::NotStarted)?;

        // Take the TUN outbound receiver, or create a dummy channel that never
        // produces messages (when TUN is disabled). Holding the sender prevents
        // the channel from closing.
        let (tun_outbound_rx, _tun_guard) = match self.tun_outbound_rx.take() {
            Some(rx) => (rx, None),
            None => {
                let (tx, rx) = crate::upper::tun::tun_outbound_channel(1);
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

        // Take the endpoint control receiver, or create a dummy channel
        // when the embedded endpoint API is not in use.
        let (mut endpoint_control_rx, _endpoint_control_guard) =
            match self.endpoint_control_rx.take() {
                Some(rx) => (rx, None),
                None => {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    (rx, Some(tx))
                }
            };
        let (endpoint_data_rx, _endpoint_data_guard) = match self.endpoint_data_rx.take() {
            Some(rx) => (rx, None),
            None => {
                let (tx, rx) = endpoint_data_batch_channel(1);
                (rx, Some(tx))
            }
        };
        let (dataplane_fast_ingress_rx, _dataplane_fast_ingress_guard) =
            match self.dataplane_fast_ingress_rx.take() {
                Some(rx) => (rx, None),
                None => {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
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

        let dataplane_endpoint_tx = self.endpoint_events.sender().unwrap_or_else(|| {
            let (tx, rx) = EndpointEventSender::channel(1);
            drop(rx);
            tx
        });
        let dataplane_readiness_notify = self.dataplane.readiness_notify();
        let mut dataplane_runtime = RxLoopDataplaneRuntime {
            packet_rx,
            dataplane_fast_ingress_rx,
            endpoint_data_rx,
            tun_outbound_rx,
            endpoint_tx: dataplane_endpoint_tx,
        };

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
                // Timer-driven liveness is a reserved-progress branch. It
                // performs bounded pre/post data drains and timeboxes slow
                // discovery/status work, so hot packet or endpoint/TUN queues
                // cannot indefinitely postpone heartbeat, rekey, MMP, route
                // aging, or path maintenance.
                _ = tick.tick() => {
                    let drained = {
                        let mut dataplane_io = dataplane_runtime.io();
                        self.drain_rx_loop_data_queues(
                            &mut dataplane_io,
                            ENDPOINT_DRAIN_BUDGET,
                        ).await
                    };
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

                    let post_drained = {
                        let mut dataplane_io = dataplane_runtime.io();
                        self.drain_rx_loop_data_queues(
                            &mut dataplane_io,
                            PACKET_DRAIN_BUDGET,
                        ).await
                    };
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
                Some(message) = control_query_rx.recv() => {
                    self.drain_control_queries(
                        &mut control_query_rx,
                        Some(message),
                        ENDPOINT_DRAIN_BUDGET,
                    ).await;
                }
                // Endpoint control carries management/lifecycle commands.
                // Endpoint payload batches stay on the data lane; this branch
                // keeps control work from waiting behind hot raw receive.
                // Endpoint data batches intentionally remain below packet_rx.
                Some(command) = endpoint_control_rx.recv() => {
                    self.handle_endpoint_control(command).await;
                }
                packet = dataplane_runtime.packet_rx.recv() => {
                    match packet {
                        Some(p) => {
                            let latency_packet = p.is_transport_priority();
                            let mut firsts = crate::dataplane::DataplaneLiveTurnFirsts {
                                raw_packet: Some(p),
                                ..Default::default()
                            };
                            if let Ok(packet) = dataplane_runtime.tun_outbound_rx.try_recv() {
                                firsts.tun_packet = Some(packet);
                            }
                            let latency_work_ready = latency_packet
                                || dataplane_runtime.packet_rx.priority_ready_packets() > 0;
                            if latency_work_ready {
                                let packet_budget = packet_drain_budget(true);
                                let endpoint_budget = endpoint_drain_budget(packet_budget);
                                let tun_budget = tun_drain_budget(packet_budget);
                                let crypto_budget = mixed_dataplane_crypto_budget(
                                    packet_budget,
                                    endpoint_budget,
                                    tun_budget,
                                );
                                let mut turn = {
                                    let mut dataplane_io = dataplane_runtime.io();
                                    self.drain_dataplane_turn_with_firsts(
                                        &mut dataplane_io,
                                        firsts,
                                        RxLoopDataplaneTurnLimits::new(
                                            packet_budget,
                                            endpoint_budget,
                                            tun_budget,
                                            crypto_budget,
                                        ),
                                    ).await
                                };
                                self.finish_dataplane_turn(
                                    &mut turn,
                                    &mut maintenance_state,
                                    &mut control_query_rx,
                                    CONTROL_QUERY_INTERLEAVE_BUDGET,
                                ).await;
                            } else {
                                firsts.raw_ingress_prefetch = true;
                                let mut dataplane_io = dataplane_runtime.io();
                                self.service_dataplane_bulk_turns(
                                    &mut dataplane_io,
                                    firsts,
                                    &mut maintenance_state,
                                    &mut control_query_rx,
                                ).await;
                            }
                        }
                        None => break, // channel closed
                    }
                }
                Some(fast_ingress) = dataplane_runtime.dataplane_fast_ingress_rx.recv() => {
                    let mut dataplane_io = dataplane_runtime.io();
                    self.service_dataplane_bulk_turns(
                        &mut dataplane_io,
                        crate::dataplane::DataplaneLiveTurnFirsts {
                            fast_ingress: Some(fast_ingress),
                            ..Default::default()
                        },
                        &mut maintenance_state,
                        &mut control_query_rx,
                    ).await;
                }
                _ = dataplane_readiness_notify.notified() => {
                    let mut dataplane_io = dataplane_runtime.io();
                    self.service_dataplane_completion_turns(
                        &mut dataplane_io,
                        &mut maintenance_state,
                        &mut control_query_rx,
                    ).await;
                }
                Some(ipv6_packet) = dataplane_runtime.tun_outbound_rx.recv() => {
                    let tun_budget = tun_drain_budget(LATENCY_PACKET_DRAIN_BUDGET);
                    let mut turn = {
                        let mut dataplane_io = dataplane_runtime.io();
                        self.drain_dataplane_turn_with_firsts(
                            &mut dataplane_io,
                            crate::dataplane::DataplaneLiveTurnFirsts {
                                tun_packet: Some(ipv6_packet),
                                ..Default::default()
                            },
                            RxLoopDataplaneTurnLimits::new(0, 0, tun_budget, tun_budget),
                        ).await
                    };
                    self.finish_dataplane_turn(
                        &mut turn,
                        &mut maintenance_state,
                        &mut control_query_rx,
                        0,
                    ).await;
                }
                Some(identity) = dns_identity_rx.recv() => {
                    debug!(
                        node_addr = %identity.node_addr,
                        "Registering identity from DNS resolution"
                    );
                    self.register_identity(identity.node_addr, identity.pubkey);
                }
                Some(batch) = dataplane_runtime.endpoint_data_rx.recv() => {
                    let mut turn = {
                        let mut dataplane_io = dataplane_runtime.io();
                        self.drain_dataplane_turn_with_firsts(
                            &mut dataplane_io,
                            crate::dataplane::DataplaneLiveTurnFirsts {
                                endpoint_data_batch: Some(batch),
                                ..Default::default()
                            },
                            RxLoopDataplaneTurnLimits::new(
                                0,
                                ENDPOINT_DRAIN_BUDGET,
                                0,
                                PACKET_DRAIN_BUDGET,
                            ),
                        ).await
                    };
                    self.finish_dataplane_turn(
                        &mut turn,
                        &mut maintenance_state,
                        &mut control_query_rx,
                        0,
                    ).await;
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
        io: &mut RxLoopDataplaneIo<'_>,
        budget: usize,
    ) -> RxLoopDataDrainStats {
        let fast_ingress =
            Self::take_dataplane_fast_ingress_batch(io.dataplane_fast_ingress_rx, budget);
        let packet_budget = budget.max(
            fast_ingress
                .as_ref()
                .map_or(0, |fast_ingress| fast_ingress.len()),
        );
        let endpoint_budget = endpoint_drain_budget(packet_budget);
        let tun_budget = tun_drain_budget(packet_budget);
        let crypto_budget =
            mixed_dataplane_crypto_budget(packet_budget, endpoint_budget, tun_budget);
        let mut turn = self
            .drain_dataplane_turn_with_firsts(
                io,
                crate::dataplane::DataplaneLiveTurnFirsts {
                    fast_ingress,
                    ..Default::default()
                },
                RxLoopDataplaneTurnLimits::new(
                    packet_budget,
                    endpoint_budget,
                    tun_budget,
                    crypto_budget,
                ),
            )
            .await;
        let drained_packets = Self::dataplane_packet_activity(&turn);
        let control_drained = self.process_dataplane_control_ingress(&mut turn).await;
        RxLoopDataDrainStats::new(
            drained_packets,
            turn.tun_source_drained(),
            turn.endpoint_source_drained(),
            control_drained,
        )
    }

    fn take_dataplane_fast_ingress_batch(
        dataplane_fast_ingress_rx: &mut crate::dataplane::DataplaneFastIngressRx,
        limit: usize,
    ) -> Option<crate::dataplane::DataplaneFastIngressBatch> {
        let fast_ingress = dataplane_fast_ingress_rx.try_recv().ok()?;
        Some(Self::coalesce_dataplane_fast_ingress(
            fast_ingress,
            dataplane_fast_ingress_rx,
            limit,
        ))
    }

    fn coalesce_dataplane_fast_ingress(
        mut fast_ingress: crate::dataplane::DataplaneFastIngressBatch,
        dataplane_fast_ingress_rx: &mut crate::dataplane::DataplaneFastIngressRx,
        limit: usize,
    ) -> crate::dataplane::DataplaneFastIngressBatch {
        while fast_ingress.len() < limit {
            let Ok(next) = dataplane_fast_ingress_rx.try_recv() else {
                break;
            };
            fast_ingress.absorb(next);
        }
        fast_ingress
    }

    async fn service_dataplane_bulk_turns(
        &mut self,
        io: &mut RxLoopDataplaneIo<'_>,
        firsts: crate::dataplane::DataplaneLiveTurnFirsts,
        maintenance_state: &mut RxLoopMaintenanceState,
        control_query_rx: &mut Receiver<ControlMessage>,
    ) {
        let started = Instant::now();
        let mut firsts = Some(firsts);
        let mut turns = 0usize;

        loop {
            if turns > 0
                && (turns >= RX_LOOP_BULK_SERVICE_MAX_TURNS
                    || started.elapsed() >= RX_LOOP_BULK_SERVICE_MAX_ELAPSED
                    || io.packet_rx.priority_ready_packets() > 0)
            {
                break;
            }

            let packet_budget = PACKET_DRAIN_BUDGET;
            let mut turn_firsts = firsts.take().unwrap_or_default();
            turn_firsts.raw_ingress_prefetch = true;
            turn_firsts.fast_ingress = match turn_firsts.fast_ingress.take() {
                Some(fast_ingress) => Some(Self::coalesce_dataplane_fast_ingress(
                    fast_ingress,
                    io.dataplane_fast_ingress_rx,
                    packet_budget,
                )),
                None => Self::take_dataplane_fast_ingress_batch(
                    io.dataplane_fast_ingress_rx,
                    packet_budget,
                ),
            };
            let packet_budget = packet_budget.max(
                turn_firsts
                    .fast_ingress
                    .as_ref()
                    .map_or(0, |fast_ingress| fast_ingress.len()),
            );
            let endpoint_budget = endpoint_drain_budget(packet_budget);
            let tun_budget = tun_drain_budget(packet_budget);
            let crypto_budget =
                mixed_dataplane_crypto_budget(packet_budget, endpoint_budget, tun_budget);

            let mut turn = self
                .drain_dataplane_turn_with_firsts(
                    io,
                    turn_firsts,
                    RxLoopDataplaneTurnLimits::new(
                        packet_budget,
                        endpoint_budget,
                        tun_budget,
                        crypto_budget,
                    ),
                )
                .await;
            let raw_drained = Self::dataplane_raw_ingress_activity(&turn);
            let control_activity = Self::dataplane_control_activity(&turn);
            let completions_drained = turn.summary().completions();
            let admission_dropped =
                turn.summary().inbound_dropped() > 0 || turn.summary().outbound_dropped() > 0;
            let keep_servicing = !admission_dropped
                && (raw_drained >= packet_budget
                    || completions_drained >= crypto_budget
                    || turn.tun_source_drained() >= tun_budget
                    || turn.endpoint_source_drained() >= endpoint_budget);
            let control_drained = self
                .finish_dataplane_turn(
                    &mut turn,
                    maintenance_state,
                    control_query_rx,
                    CONTROL_QUERY_INTERLEAVE_BUDGET,
                )
                .await;
            turns += 1;
            let mut runnable_work = self.dataplane.has_runnable_work();

            if control_drained == 0
                && bulk_admission_pressure_relief_due(
                    admission_dropped,
                    runnable_work,
                    turns,
                    started.elapsed(),
                    io.packet_rx.priority_ready_packets(),
                )
            {
                let mut relief_turn = self
                    .drain_dataplane_completion_turn(io, LATENCY_PACKET_DRAIN_BUDGET)
                    .await;
                let relief_control_drained = self
                    .finish_dataplane_turn(&mut relief_turn, maintenance_state, control_query_rx, 0)
                    .await;
                turns += 1;
                runnable_work = self.dataplane.has_runnable_work();
                if relief_control_drained > 0 || !runnable_work {
                    break;
                }
            }

            if control_drained > 0
                || admission_dropped
                || (!keep_servicing && !runnable_work)
                || (control_activity > 0 && !runnable_work)
            {
                break;
            }
        }
    }

    async fn service_dataplane_completion_turns(
        &mut self,
        io: &mut RxLoopDataplaneIo<'_>,
        maintenance_state: &mut RxLoopMaintenanceState,
        control_query_rx: &mut Receiver<ControlMessage>,
    ) {
        let started = Instant::now();
        let mut turns = 0usize;

        loop {
            if turns > 0
                && (turns >= RX_LOOP_BULK_SERVICE_MAX_TURNS
                    || started.elapsed() >= RX_LOOP_BULK_SERVICE_MAX_ELAPSED
                    || io.packet_rx.priority_ready_packets() > 0)
            {
                break;
            }

            let mut turn = self
                .drain_dataplane_completion_turn(io, LATENCY_PACKET_DRAIN_BUDGET)
                .await;
            let control_drained = self
                .finish_dataplane_turn(&mut turn, maintenance_state, control_query_rx, 0)
                .await;
            turns += 1;

            let runnable_work = self.dataplane.has_runnable_work();
            if control_drained > 0 || !runnable_work {
                break;
            }
        }
    }

    async fn finish_dataplane_turn(
        &mut self,
        turn: &mut crate::dataplane::DataplaneLiveNodeTurn,
        maintenance_state: &mut RxLoopMaintenanceState,
        control_query_rx: &mut Receiver<ControlMessage>,
        control_query_budget: usize,
    ) -> usize {
        let had_activity = turn.has_activity();
        let control_drained = self
            .process_dataplane_control_ingress(turn)
            .await
            .saturating_add(self.drain_deferred_dataplane_control_turns().await);
        if control_drained > 0 && self.dataplane.has_deferred_raw_ingress() {
            self.dataplane.readiness_notify().notify_one();
        }
        let query_drained = if control_query_budget > 0 {
            self.drain_control_queries(control_query_rx, None, control_query_budget)
                .await
        } else {
            0
        };
        if had_activity || control_drained > 0 {
            maintenance_state.record_data_activity(Instant::now());
        }
        control_drained.saturating_add(query_drained)
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

    async fn run_rx_loop_maintenance_tick(&mut self, plan: RxLoopMaintenancePlan) -> bool {
        if !rx_loop_fast_maintenance_within_budget(self.run_rx_loop_fast_maintenance_tick()).await {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::RxLoopSlowMaintenanceTimeout,
            );
            self.mark_rx_loop_maintenance_timeout();
            warn!(
                timeout_ms = RX_LOOP_FAST_MAINTENANCE_TIMEOUT.as_millis() as u64,
                data_pressure = plan.data_pressure(),
                "RX loop liveness maintenance timed out; continuing packet processing"
            );
            return true;
        }

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

    async fn run_rx_loop_fast_maintenance_tick(&mut self) {
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
        self.retry_pending_session_traffic().await;
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
        self.sample_transport_congestion();
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
        self.poll_local_rendezvous().await;
        self.check_tree_state().await;
        self.check_bloom_state().await;
        self.compute_mesh_size();
        self.record_stats_history();
    }
}

async fn rx_loop_fast_maintenance_within_budget<F>(maintenance: F) -> bool
where
    F: std::future::Future<Output = ()>,
{
    tokio::time::timeout(RX_LOOP_FAST_MAINTENANCE_TIMEOUT, maintenance)
        .await
        .is_ok()
}

fn bulk_admission_pressure_relief_due(
    admission_dropped: bool,
    runnable_work: bool,
    turns: usize,
    elapsed: Duration,
    priority_ready_packets: usize,
) -> bool {
    admission_dropped
        && runnable_work
        && turns < RX_LOOP_BULK_SERVICE_MAX_TURNS
        && elapsed < RX_LOOP_BULK_SERVICE_MAX_ELAPSED
        && priority_ready_packets == 0
}
