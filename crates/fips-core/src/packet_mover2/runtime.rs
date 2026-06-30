#[derive(Debug)]
pub(crate) struct PacketMover2TurnDriver {
    mover: PacketMover2,
    prepared_work: Vec<PreparedCryptoWork>,
    completion_work: Vec<CryptoCompletion>,
    raw_ingress_drops: Vec<PacketMover2RawIngressDrop>,
    output_drops: Vec<PacketMover2OutputDrop>,
    outputs: Vec<PacketOutput>,
    output_rewrite_buffer: Vec<PacketOutput>,
    retired: Vec<RetiredPacket>,
    transport_output: PacketMover2TransportSendPlanOutput,
    drops: Vec<PacketDrop>,
    fmp_ingress_receipts: Vec<PacketMover2FmpIngressReceipt>,
    fmp_link_ingress: Vec<PacketMover2FmpLinkIngress>,
    fsp_coord_warmups: Vec<PacketMover2FspCoordWarmup>,
    fsp_local_session_ingress: Vec<PacketMover2FspLocalSessionIngress>,
    fsp_session_ingress: Vec<PacketMover2FspSessionIngress>,
}

impl PacketMover2TurnDriver {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            mover: PacketMover2::new(config),
            prepared_work: Vec::new(),
            completion_work: Vec::new(),
            raw_ingress_drops: Vec::new(),
            output_drops: Vec::new(),
            outputs: Vec::new(),
            output_rewrite_buffer: Vec::new(),
            retired: Vec::new(),
            transport_output: PacketMover2TransportSendPlanOutput::new(),
            drops: Vec::new(),
            fmp_ingress_receipts: Vec::new(),
            fmp_link_ingress: Vec::new(),
            fsp_coord_warmups: Vec::new(),
            fsp_local_session_ingress: Vec::new(),
            fsp_session_ingress: Vec::new(),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.mover.register_owner(owner, config);
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> bool {
        self.mover.unregister_owner(owner)
    }

    pub(crate) fn has_owner(&self, owner: OwnerId) -> bool {
        self.mover.has_owner(owner)
    }

    pub(crate) fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.mover.owner_active_path(owner)
    }

    pub(crate) fn owner_fsp_activity(
        &self,
        owner: OwnerId,
    ) -> Option<PacketMover2FspOwnerActivity> {
        self.mover.owner_fsp_activity(owner)
    }

    pub(crate) fn min_fsp_rx_age_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
    ) -> Option<u64> {
        self.mover.min_fsp_rx_age_for_next_hop(next_hop, now_ms)
    }

    pub(crate) fn min_fsp_data_rx_age_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
    ) -> Option<u64> {
        self.mover
            .min_fsp_data_rx_age_for_next_hop(next_hop, now_ms)
    }

    pub(crate) fn any_fsp_recent_outbound_without_inbound_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
        timeout_ms: u64,
    ) -> bool {
        self.mover
            .any_fsp_recent_outbound_without_inbound_for_next_hop(next_hop, now_ms, timeout_ms)
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.mover.owner_mut(owner)
    }

    pub(crate) fn record_authenticated_fsp_session(
        &mut self,
        owner: OwnerId,
        previous_hop: NodeAddr,
        msg_type: u8,
        body_len: usize,
        activity_tick: Option<ActivityTick>,
    ) -> bool {
        self.mover
            .record_authenticated_fsp_session(owner, previous_hop, msg_type, body_len, activity_tick)
    }

    pub(crate) fn record_fsp_data_sent(
        &mut self,
        owner: OwnerId,
        next_hop: NodeAddr,
        bytes: usize,
        tick: ActivityTick,
    ) -> bool {
        self.mover.record_fsp_data_sent(owner, next_hop, bytes, tick)
    }

    async fn finish_aead_live_node_output_turn_with_executor<Resolver, Transports, E>(
        &mut self,
        summary: PacketMover2RuntimeSummary,
        routes: &mut PacketMover2LiveRouteTable,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        endpoint_resolver: Resolver,
        transports: &Transports,
        crypto_limit: usize,
        collect_transport_sent_outputs: bool,
        executor: &mut E,
        transport_send_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
        Resolver: PacketMover2EndpointIdentityResolver,
        Transports: PacketMover2TransportResolver + ?Sized,
        E: PacketMover2CryptoExecutor,
    {
        let mut summary =
            self.collect_live_session_outputs_with_executor(summary, routes, crypto_limit, executor);
        self.collect_fsp_session_payload_outputs(&mut summary);
        let mut transport_output = std::mem::take(&mut self.transport_output);
        transport_output.clear();
        let mut report = {
            let tun_output = PacketMover2TunTxOutput::new(tun_tx);
            let endpoint_output =
                PacketMover2EndpointEventOutput::new(endpoint_tx, endpoint_resolver);
            let mut sink =
                PacketMover2LiveOutputSink::new(tun_output, endpoint_output, &mut transport_output);
            let turn = self.send_collected_outputs(summary, &mut sink);
            PacketMover2LiveNodeTurn::from_runtime_turn(&turn)
        };
        report.set_fmp_ingress_receipts(std::mem::take(&mut self.fmp_ingress_receipts));
        report.set_fmp_link_ingress(std::mem::take(&mut self.fmp_link_ingress));
        report.set_fsp_coord_warmups(std::mem::take(&mut self.fsp_coord_warmups));
        report.set_fsp_local_session_ingress(std::mem::take(&mut self.fsp_local_session_ingress));
        report.set_fsp_session_ingress(std::mem::take(&mut self.fsp_session_ingress));
        report.transport_planned = transport_output.plans().len();
        let dropped_before = report.output_drops.len();
        report.transport_sent = {
            let _transport_send_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::PacketMover2TransportSend,
            );
            if collect_transport_sent_outputs {
                let plans = transport_output.take_plans_preserving_capacity();
                send_packet_mover2_transport_plans_with_bulk_worker(
                    transports,
                    plans,
                    &mut report.output_drops,
                    transport_send_worker,
                    Some(&mut report.transport_sent_outputs),
                )
                .await
            } else {
                let plans = transport_output.take_plans_preserving_capacity();
                send_packet_mover2_transport_plans_with_bulk_worker(
                    transports,
                    plans,
                    &mut report.output_drops,
                    transport_send_worker,
                    None,
                )
                .await
            }
        };
        report.transport_dropped = report.output_drops.len().saturating_sub(dropped_before);
        debug_assert_eq!(
            report.transport_planned,
            report.transport_sent + report.transport_dropped
        );
        report.summary.outputs_sent = report
            .summary
            .outputs_sent
            .saturating_sub(report.transport_dropped);
        report.summary.outputs_dropped = report
            .summary
            .outputs_dropped
            .saturating_add(report.transport_dropped);
        self.transport_output = transport_output;
        report
    }

    async fn pump_aead_live_node_route_table_completion_executor_turn_with_firsts<
        C,
        E,
        RI,
        Resolver,
        Transports,
    >(
        &mut self,
        completions: &mut C,
        completion_limit: usize,
        executor: &mut E,
        raw_ingress: &mut RI,
        routes: &mut PacketMover2LiveRouteTable,
        raw_ingress_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        outbound_firsts: PacketMover2LiveOutboundFirsts,
        deferred_endpoint_commands: &mut Vec<NodeEndpointCommand>,
        deferred_tun_packets: &mut Vec<Vec<u8>>,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        endpoint_resolver: Resolver,
        transports: &Transports,
        crypto_limit: usize,
        transport_send_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
        C: PacketMover2CompletionSource,
        E: PacketMover2CryptoExecutor,
        RI: PacketMover2RawIngressSource,
        Resolver: PacketMover2EndpointIdentityResolver,
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        let summary = self.start_aead_completion_turn(completions, completion_limit);
        self.pump_aead_live_node_route_table_executor_turn_after_completion_with_firsts(
            summary,
            executor,
            raw_ingress,
            routes,
            raw_ingress_limit,
            endpoint_priority_rx,
            endpoint_bulk_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            outbound_firsts,
            deferred_endpoint_commands,
            deferred_tun_packets,
            tun_tx,
            endpoint_tx,
            endpoint_resolver,
            transports,
            crypto_limit,
            transport_send_worker,
        )
        .await
    }

    fn start_aead_completion_turn<C>(
        &mut self,
        completions: &mut C,
        completion_limit: usize,
    ) -> PacketMover2RuntimeSummary
    where
        C: PacketMover2CompletionSource,
    {
        let _completion_timer = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::PacketMover2CompletionDrain,
        );
        self.reset_turn_buffers();
        let mut summary = PacketMover2RuntimeSummary::default();
        completions.drain_completions(completion_limit, |completion| {
            self.collect_completed_aead_output(&mut summary, completion);
        });
        self.collect_retired_outputs(summary)
    }

    async fn pump_aead_live_node_route_table_executor_turn_after_completion_with_firsts<
        E,
        RI,
        Resolver,
        Transports,
    >(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        executor: &mut E,
        raw_ingress: &mut RI,
        routes: &mut PacketMover2LiveRouteTable,
        raw_ingress_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        outbound_firsts: PacketMover2LiveOutboundFirsts,
        deferred_endpoint_commands: &mut Vec<NodeEndpointCommand>,
        deferred_tun_packets: &mut Vec<Vec<u8>>,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        endpoint_resolver: Resolver,
        transports: &Transports,
        crypto_limit: usize,
        transport_send_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
        E: PacketMover2CryptoExecutor,
        RI: PacketMover2RawIngressSource,
        Resolver: PacketMover2EndpointIdentityResolver,
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        let admit_timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2LiveAdmit);
        let mut outbound_firsts = outbound_firsts;
        let collect_transport_sent_outputs = outbound_firsts.collect_transport_sent_outputs();
        if let Some(packet) = outbound_firsts.take_initial_outbound() {
            self.admit_outbound_packet(packet, &mut summary);
        }

        let routed_outbound_limit = endpoint_limit.saturating_add(tun_limit);
        let outbound_limit = routed_outbound_limit;
        let reserved_outbound_limit =
            reserved_live_outbound_progress_limit(endpoint_limit, tun_limit, routed_outbound_limit);
        let mut outbound_buffers = PacketMover2RouteTableOutboundBuffers::default();
        let mut endpoint_drained = 0usize;
        let mut tun_drained = 0usize;
        let mut outbound_drained = 0usize;

        if reserved_outbound_limit > 0 {
            let mut outbound_source = PacketMover2RouteTableOutboundSource::new(
                endpoint_priority_rx,
                endpoint_bulk_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                routes,
            )
            .with_firsts(outbound_firsts)
            .with_report_buffers(outbound_buffers);
            outbound_drained = outbound_source.drain_outbound(reserved_outbound_limit, |packet| {
                self.admit_outbound_packet(packet, &mut summary);
            });
            endpoint_drained = endpoint_drained.saturating_add(outbound_source.endpoint_drained());
            tun_drained = tun_drained.saturating_add(outbound_source.tun_drained());
            outbound_firsts = outbound_source.take_firsts();
            outbound_buffers = outbound_source.take_report_buffers();
        }

        raw_ingress.drain_raw_ingress(raw_ingress_limit, |packet| {
            self.admit_raw_ingress_packet(packet, routes, &mut summary);
        });

        let remaining_outbound_limit =
            outbound_limit.saturating_sub(outbound_drained.min(outbound_limit));
        if remaining_outbound_limit > 0 {
            let mut outbound_source = PacketMover2RouteTableOutboundSource::new(
                endpoint_priority_rx,
                endpoint_bulk_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                routes,
            )
            .with_firsts(outbound_firsts)
            .with_report_buffers(outbound_buffers);
            outbound_source.drain_outbound(remaining_outbound_limit, |packet| {
                self.admit_outbound_packet(packet, &mut summary);
            });
            endpoint_drained = endpoint_drained.saturating_add(outbound_source.endpoint_drained());
            tun_drained = tun_drained.saturating_add(outbound_source.tun_drained());
            outbound_buffers = outbound_source.take_report_buffers();
        }
        drop(admit_timer);

        let mut report = self
            .finish_aead_live_node_output_turn_with_executor(
                summary,
                routes,
                tun_tx,
                endpoint_tx,
                endpoint_resolver,
                transports,
                crypto_limit,
                collect_transport_sent_outputs,
                executor,
                transport_send_worker,
            )
            .await;
        let endpoint_deferred_count = outbound_buffers.endpoint_deferred_commands.len();
        deferred_endpoint_commands.append(&mut outbound_buffers.endpoint_deferred_commands);
        let tun_deferred_count = outbound_buffers.tun_deferred_packets.len();
        deferred_tun_packets.append(&mut outbound_buffers.tun_deferred_packets);
        report.set_endpoint_command_drops(outbound_buffers.endpoint_drops);
        report.set_endpoint_source_drained(endpoint_drained);
        report.set_endpoint_deferred_commands(endpoint_deferred_count);
        report.set_tun_outbound_drops(outbound_buffers.tun_drops);
        report.set_tun_deferred_packets(tun_deferred_count);
        report.set_tun_source_drained(tun_drained);
        report
    }

    fn admit_raw_ingress_turn<I, O, R>(
        &mut self,
        inbound: I,
        router: &mut R,
        outbound: O,
    ) -> PacketMover2RuntimeSummary
    where
        I: IntoIterator<Item = PacketMover2RawIngress>,
        O: IntoIterator<Item = OutboundPacket>,
        R: PacketMover2IngressRouter,
    {
        let mut summary = PacketMover2RuntimeSummary::default();
        for packet in inbound {
            self.admit_raw_ingress_packet(packet, router, &mut summary);
        }
        for packet in outbound {
            self.admit_outbound_packet(packet, &mut summary);
        }
        summary
    }

    fn reset_turn_buffers(&mut self) {
        self.outputs.clear();
        self.output_rewrite_buffer.clear();
        self.retired.clear();
        self.transport_output.clear();
        self.drops.clear();
        self.raw_ingress_drops.clear();
        self.output_drops.clear();
        self.fmp_ingress_receipts.clear();
        self.fmp_link_ingress.clear();
        self.fsp_coord_warmups.clear();
        self.fsp_local_session_ingress.clear();
        self.fsp_session_ingress.clear();
    }

    fn admit_raw_ingress_packet<R>(
        &mut self,
        packet: PacketMover2RawIngress,
        router: &mut R,
        summary: &mut PacketMover2RuntimeSummary,
    ) where
        R: PacketMover2IngressRouter,
    {
        let header = match packet.protocol {
            PacketProtocol::Fmp => match FmpWireHeader::parse(&packet.payload) {
                Ok(header) => PacketMover2IngressHeader::Fmp(header),
                Err(error) => {
                    summary.raw_ingress_dropped += 1;
                    self.raw_ingress_drops
                        .push(PacketMover2RawIngressDrop::from_packet(
                            packet,
                            PacketMover2RawIngressDropReason::Wire(error),
                        ));
                    return;
                }
            },
            PacketProtocol::Fsp => match FspWireHeader::parse(&packet.payload) {
                Ok(header) => PacketMover2IngressHeader::Fsp(header),
                Err(error) => {
                    summary.raw_ingress_dropped += 1;
                    self.raw_ingress_drops
                        .push(PacketMover2RawIngressDrop::from_packet(
                            packet,
                            PacketMover2RawIngressDropReason::Wire(error),
                        ));
                    return;
                }
            },
        };

        let Some(route) = router.route(&packet, header) else {
            summary.raw_ingress_dropped += 1;
            self.raw_ingress_drops
                .push(PacketMover2RawIngressDrop::from_packet(
                    packet,
                    PacketMover2RawIngressDropReason::Unrouted,
                ));
            return;
        };

        let wire_flags = header.flags();
        let PacketMover2RawIngress {
            path: source_path,
            previous_hop,
            ce_flag,
            path_mtu,
            activity_tick,
            payload,
            ..
        } = packet;
        let mut socket_packet = SocketPacket::new(
            route.owner,
            route.generation,
            header.counter(),
            route.class,
            route.output,
            payload,
        )
        .with_source_path(source_path);
        socket_packet = socket_packet.with_path_mtu(path_mtu);
        if let Some(tick) = activity_tick {
            socket_packet = socket_packet.with_activity_tick(tick);
        }
        if let Some(previous_hop) = previous_hop {
            socket_packet = socket_packet.with_previous_hop(previous_hop);
        }
        socket_packet = socket_packet.with_ce_flag(ce_flag);
        socket_packet = socket_packet.with_wire_flags(wire_flags);
        self.admit_socket_packet(socket_packet, summary);
    }

    fn admit_socket_packet(
        &mut self,
        packet: SocketPacket,
        summary: &mut PacketMover2RuntimeSummary,
    ) {
        match self.mover.submit_socket_packet(packet) {
            Ok(_) => summary.inbound_admitted += 1,
            Err(_) => summary.inbound_dropped += 1,
        }
    }

    fn admit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
        summary: &mut PacketMover2RuntimeSummary,
    ) {
        match self.mover.submit_outbound_packet(packet) {
            Ok(_) => summary.outbound_admitted += 1,
            Err(_) => summary.outbound_dropped += 1,
        }
    }

    fn send_collected_outputs<S>(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        sink: &mut S,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        S: PacketMover2OutputSink,
    {
        let dropped_before = self.output_drops.len();
        let sent = {
            let _output_sink_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::PacketMover2OutputSink,
            );
            sink.send_batch(self.outputs.drain(..), &mut self.output_drops)
        };
        summary.outputs_sent += sent;
        summary.outputs_dropped += self.output_drops.len().saturating_sub(dropped_before);

        PacketMover2RuntimeTurn {
            summary,
            raw_ingress_drops: &self.raw_ingress_drops,
            output_drops: &self.output_drops,
            outputs: &self.outputs,
            drops: &self.drops,
        }
    }

    fn admit_session_ingress_outputs<R>(
        &mut self,
        router: &mut R,
        summary: &mut PacketMover2RuntimeSummary,
    ) -> usize
    where
        R: PacketMover2IngressRouter,
    {
        let mut outputs = self.take_outputs_for_rewrite();
        let dropped_before = self.output_drops.len();
        let admitted_before = summary.inbound_admitted;
        for output in outputs.drain(..) {
            match output.target {
                OutputTarget::SessionIngress { local_addr } => {
                    let receipt = PacketMover2FmpIngressReceipt::from_output(&output);
                    match packet_mover2_session_ingress_from_output(output, local_addr) {
                        Ok(PacketMover2SessionIngressHandoff::Raw { raw, coord_warmup }) => {
                            if let Some(receipt) = receipt {
                                self.fmp_ingress_receipts.push(receipt);
                            }
                            if !coord_warmup.is_empty() {
                                self.fsp_coord_warmups.push(coord_warmup);
                            }
                            self.admit_raw_ingress_packet(raw, router, summary);
                        }
                        Ok(PacketMover2SessionIngressHandoff::Local(ingress)) => {
                            if let Some(receipt) = receipt {
                                self.fmp_ingress_receipts.push(receipt);
                            }
                            self.fsp_local_session_ingress.push(ingress);
                        }
                        Err((output, PacketMover2SessionHandoffError::NoRoute)) => {
                            match PacketMover2FmpLinkIngress::from_output(output) {
                                Ok(ingress) => self.fmp_link_ingress.push(ingress),
                                Err(output) => {
                                    self.output_drops.push(PacketMover2OutputDrop::from_output(
                                        &output,
                                        PacketMover2OutputError::NoRoute,
                                    ));
                                }
                            }
                        }
                        Err((output, error)) => {
                            self.output_drops.push(PacketMover2OutputDrop::from_output(
                                &output,
                                packet_mover2_output_error_from_session_handoff(error),
                            ))
                        }
                    }
                }
                _ => self.outputs.push(output),
            }
        }
        self.output_rewrite_buffer = outputs;
        summary.outputs = self.outputs.len();
        summary.outputs_dropped = summary
            .outputs_dropped
            .saturating_add(self.output_drops.len().saturating_sub(dropped_before));
        summary.inbound_admitted.saturating_sub(admitted_before)
    }

    fn collect_fsp_session_payload_outputs(&mut self, summary: &mut PacketMover2RuntimeSummary) {
        let mut outputs = self.take_outputs_for_rewrite();
        let dropped_before = self.output_drops.len();
        for output in outputs.drain(..) {
            match output.target {
                OutputTarget::SessionPayload { .. } => {
                    match PacketMover2FspSessionIngress::from_output(output) {
                        Ok(ingress) => self.fsp_session_ingress.push(ingress),
                        Err(output) => {
                            self.output_drops.push(PacketMover2OutputDrop::from_output(
                                &output,
                                PacketMover2OutputError::InvalidPacket,
                            ));
                        }
                    }
                }
                _ => self.outputs.push(output),
            }
        }
        self.output_rewrite_buffer = outputs;
        summary.outputs = self.outputs.len();
        summary.outputs_dropped = summary
            .outputs_dropped
            .saturating_add(self.output_drops.len().saturating_sub(dropped_before));
    }

    fn collect_completed_aead_outputs<I>(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        completions: I,
    ) -> PacketMover2RuntimeSummary
    where
        I: IntoIterator<Item = CryptoCompletion>,
    {
        for completion in completions {
            self.collect_completed_aead_output(&mut summary, completion);
        }
        self.collect_retired_outputs(summary)
    }

    fn collect_completed_aead_output(
        &mut self,
        summary: &mut PacketMover2RuntimeSummary,
        completion: CryptoCompletion,
    ) {
        self.retire_completion_collecting_drops(completion);
        summary.completions = summary.completions.saturating_add(1);
    }

    fn retire_completion_collecting_drops(&mut self, completion: CryptoCompletion) {
        let retired_start = self.retired.len();
        self.mover
            .retire_completion_into(completion, &mut self.retired);
        let mut mover_drops = self.mover.drain_drops();
        let emitted_drop_start = self.drops.len();
        self.drops.append(&mut mover_drops);
        for item in &self.retired[retired_start..] {
            if let RetiredPacket::Drop(drop) = item
                && !self.drops[emitted_drop_start..]
                    .iter()
                    .any(|emitted| emitted == drop)
            {
                self.drops.push(drop.clone());
            }
        }
    }

    fn collect_live_session_outputs_with_executor<R, E>(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        router: &mut R,
        crypto_limit: usize,
        executor: &mut E,
    ) -> PacketMover2RuntimeSummary
    where
        R: PacketMover2IngressRouter,
        E: PacketMover2CryptoExecutor,
    {
        let mut remaining = crypto_limit;
        loop {
            let dispatched_before = summary.dispatched;
            summary = self.collect_aead_outputs_with_executor(summary, remaining, executor);
            let dispatched = summary.dispatched.saturating_sub(dispatched_before);
            remaining = remaining.saturating_sub(dispatched);
            if remaining == 0 {
                break;
            }

            if self.admit_session_ingress_outputs(router, &mut summary) == 0 {
                break;
            }
        }
        summary
    }

    fn take_outputs_for_rewrite(&mut self) -> Vec<PacketOutput> {
        let mut outputs = std::mem::take(&mut self.output_rewrite_buffer);
        std::mem::swap(&mut self.outputs, &mut outputs);
        outputs
    }

    fn collect_aead_outputs_with_executor<E>(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        limit: usize,
        executor: &mut E,
    ) -> PacketMover2RuntimeSummary
    where
        E: PacketMover2CryptoExecutor,
    {
        let mut remaining = limit;
        while remaining > 0 {
            let dispatched = {
                let _dispatch_timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadDispatch,
                );
                self.mover.run_aead_available_into_with_executor(
                    remaining,
                    &mut self.prepared_work,
                    &mut self.completion_work,
                    &mut self.retired,
                    &mut self.drops,
                    executor,
                )
            };
            summary.dispatched = summary.dispatched.saturating_add(dispatched);
            remaining = remaining.saturating_sub(dispatched);

            let outbound_admitted_before = summary.outbound_admitted;
            summary = self.collect_retired_outputs(summary);

            if dispatched == 0 && summary.outbound_admitted == outbound_admitted_before {
                break;
            }
        }

        summary.outputs = self.outputs.len();
        summary.drops = self.drops.len();
        summary
    }

    fn collect_retired_outputs(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
    ) -> PacketMover2RuntimeSummary {
        let mut retired = std::mem::take(&mut self.retired);
        for packet in retired.drain(..) {
            match packet {
                RetiredPacket::Output(mut output) => {
                    output.promote_opened_latency_sensitive_payload();
                    self.outputs.push(output);
                }
                RetiredPacket::Outbound(packet) => {
                    self.admit_outbound_packet(packet, &mut summary);
                }
                RetiredPacket::Drop(_) => {}
            }
        }
        self.retired = retired;
        summary.outputs = self.outputs.len();
        summary.drops = self.drops.len();
        summary
    }
}
