#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PacketMover2RuntimeSummary {
    raw_ingress_dropped: usize,
    inbound_admitted: usize,
    inbound_dropped: usize,
    outbound_admitted: usize,
    outbound_dropped: usize,
    dispatched: usize,
    outputs: usize,
    outputs_sent: usize,
    outputs_dropped: usize,
    drops: usize,
}

impl PacketMover2RuntimeSummary {
    pub(crate) fn raw_ingress_dropped(self) -> usize {
        self.raw_ingress_dropped
    }

    pub(crate) fn inbound_admitted(self) -> usize {
        self.inbound_admitted
    }

    pub(crate) fn inbound_dropped(self) -> usize {
        self.inbound_dropped
    }

    pub(crate) fn outbound_admitted(self) -> usize {
        self.outbound_admitted
    }

    pub(crate) fn outbound_dropped(self) -> usize {
        self.outbound_dropped
    }

    pub(crate) fn dispatched(self) -> usize {
        self.dispatched
    }

    pub(crate) fn outputs(self) -> usize {
        self.outputs
    }

    pub(crate) fn outputs_sent(self) -> usize {
        self.outputs_sent
    }

    pub(crate) fn outputs_dropped(self) -> usize {
        self.outputs_dropped
    }

    pub(crate) fn drops(self) -> usize {
        self.drops
    }

    pub(crate) fn has_activity(self) -> bool {
        self.raw_ingress_dropped > 0
            || self.inbound_admitted > 0
            || self.inbound_dropped > 0
            || self.outbound_admitted > 0
            || self.outbound_dropped > 0
            || self.dispatched > 0
            || self.outputs > 0
            || self.outputs_sent > 0
            || self.outputs_dropped > 0
            || self.drops > 0
    }

    pub(crate) fn has_failures(self) -> bool {
        self.raw_ingress_dropped > 0
            || self.inbound_dropped > 0
            || self.outbound_dropped > 0
            || self.outputs_dropped > 0
            || self.drops > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2RuntimeTurn<'a> {
    summary: PacketMover2RuntimeSummary,
    raw_ingress_drops: &'a [PacketMover2RawIngressDrop],
    output_drops: &'a [PacketMover2OutputDrop],
    outputs: &'a [PacketOutput],
    drops: &'a [PacketDrop],
}

impl PacketMover2RuntimeTurn<'_> {
    pub(crate) fn summary(&self) -> PacketMover2RuntimeSummary {
        self.summary
    }

    pub(crate) fn raw_ingress_drops(&self) -> &[PacketMover2RawIngressDrop] {
        self.raw_ingress_drops
    }

    pub(crate) fn output_drops(&self) -> &[PacketMover2OutputDrop] {
        self.output_drops
    }

    pub(crate) fn outputs(&self) -> &[PacketOutput] {
        self.outputs
    }

    pub(crate) fn drops(&self) -> &[PacketDrop] {
        self.drops
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PacketMover2LiveNodeTurn {
    summary: PacketMover2RuntimeSummary,
    fmp_control_ingress: Vec<PacketMover2FmpControlIngress>,
    raw_ingress_drops: Vec<PacketMover2RawIngressDrop>,
    tun_outbound_drops: Vec<PacketMover2TunOutboundDrop>,
    endpoint_command_drops: Vec<PacketMover2EndpointCommandDrop>,
    endpoint_deferred_commands: usize,
    output_drops: Vec<PacketMover2OutputDrop>,
    drops: Vec<PacketDrop>,
    transport_planned: usize,
    transport_sent: usize,
    transport_dropped: usize,
}

impl PacketMover2LiveNodeTurn {
    fn from_runtime_turn(turn: &PacketMover2RuntimeTurn<'_>) -> Self {
        Self {
            summary: turn.summary(),
            fmp_control_ingress: Vec::new(),
            raw_ingress_drops: turn.raw_ingress_drops().to_vec(),
            tun_outbound_drops: Vec::new(),
            endpoint_command_drops: Vec::new(),
            endpoint_deferred_commands: 0,
            output_drops: turn.output_drops().to_vec(),
            drops: turn.drops().to_vec(),
            transport_planned: 0,
            transport_sent: 0,
            transport_dropped: 0,
        }
    }

    pub(crate) fn summary(&self) -> PacketMover2RuntimeSummary {
        self.summary
    }

    pub(crate) fn raw_ingress_drops(&self) -> &[PacketMover2RawIngressDrop] {
        &self.raw_ingress_drops
    }

    pub(crate) fn fmp_control_ingress(&self) -> &[PacketMover2FmpControlIngress] {
        &self.fmp_control_ingress
    }

    fn set_fmp_control_ingress(&mut self, ingress: Vec<PacketMover2FmpControlIngress>) {
        self.fmp_control_ingress = ingress;
    }

    pub(crate) fn take_fmp_control_ingress(&mut self) -> Vec<PacketMover2FmpControlIngress> {
        std::mem::take(&mut self.fmp_control_ingress)
    }

    pub(crate) fn tun_outbound_drops(&self) -> &[PacketMover2TunOutboundDrop] {
        &self.tun_outbound_drops
    }

    fn set_tun_outbound_drops(&mut self, drops: Vec<PacketMover2TunOutboundDrop>) {
        self.tun_outbound_drops = drops;
    }

    pub(crate) fn endpoint_command_drops(&self) -> &[PacketMover2EndpointCommandDrop] {
        &self.endpoint_command_drops
    }

    fn set_endpoint_command_drops(&mut self, drops: Vec<PacketMover2EndpointCommandDrop>) {
        self.endpoint_command_drops = drops;
    }

    pub(crate) fn endpoint_deferred_commands(&self) -> usize {
        self.endpoint_deferred_commands
    }

    fn set_endpoint_deferred_commands(&mut self, count: usize) {
        self.endpoint_deferred_commands = count;
    }

    pub(crate) fn output_drops(&self) -> &[PacketMover2OutputDrop] {
        &self.output_drops
    }

    pub(crate) fn drops(&self) -> &[PacketDrop] {
        &self.drops
    }

    pub(crate) fn transport_planned(&self) -> usize {
        self.transport_planned
    }

    pub(crate) fn transport_sent(&self) -> usize {
        self.transport_sent
    }

    pub(crate) fn transport_dropped(&self) -> usize {
        self.transport_dropped
    }

    pub(crate) fn has_activity(&self) -> bool {
        self.summary.has_activity()
            || !self.fmp_control_ingress.is_empty()
            || !self.raw_ingress_drops.is_empty()
            || !self.tun_outbound_drops.is_empty()
            || !self.endpoint_command_drops.is_empty()
            || self.endpoint_deferred_commands > 0
            || !self.output_drops.is_empty()
            || !self.drops.is_empty()
            || self.transport_planned > 0
            || self.transport_sent > 0
            || self.transport_dropped > 0
    }

    pub(crate) fn has_failures(&self) -> bool {
        self.summary.has_failures()
            || !self.raw_ingress_drops.is_empty()
            || !self.tun_outbound_drops.is_empty()
            || !self.endpoint_command_drops.is_empty()
            || !self.output_drops.is_empty()
            || !self.drops.is_empty()
            || self.transport_dropped > 0
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2TurnDriver<W = CopyCryptoWorker> {
    mover: PacketMover2<W>,
    open_work: Vec<CryptoWork>,
    seal_work: Vec<OutboundCryptoWork>,
    raw_ingress_drops: Vec<PacketMover2RawIngressDrop>,
    output_drops: Vec<PacketMover2OutputDrop>,
    outputs: Vec<PacketOutput>,
    drops: Vec<PacketDrop>,
}

impl<W: StatelessCryptoWorker> PacketMover2TurnDriver<W> {
    pub(crate) fn new(config: AdmissionConfig, worker: W) -> Self {
        Self {
            mover: PacketMover2::new(config, worker),
            open_work: Vec::new(),
            seal_work: Vec::new(),
            raw_ingress_drops: Vec::new(),
            output_drops: Vec::new(),
            outputs: Vec::new(),
            drops: Vec::new(),
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

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.mover.owner_mut(owner)
    }

    pub(crate) fn mover_mut(&mut self) -> &mut PacketMover2<W> {
        &mut self.mover
    }

    pub(crate) fn run_aead_classified_turn<I, O>(
        &mut self,
        inbound: I,
        outbound: O,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        I: IntoIterator<Item = SocketPacket>,
        O: IntoIterator<Item = OutboundPacket>,
    {
        self.reset_turn_buffers();

        let mut summary = PacketMover2RuntimeSummary::default();
        for packet in inbound {
            self.admit_socket_packet(packet, &mut summary);
        }
        for packet in outbound {
            self.admit_outbound_packet(packet, &mut summary);
        }

        self.finish_aead_turn(summary, limit)
    }

    pub(crate) fn run_aead_classified_output_turn<I, O, S>(
        &mut self,
        inbound: I,
        outbound: O,
        sink: &mut S,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        I: IntoIterator<Item = SocketPacket>,
        O: IntoIterator<Item = OutboundPacket>,
        S: PacketMover2OutputSink,
    {
        self.reset_turn_buffers();

        let mut summary = PacketMover2RuntimeSummary::default();
        for packet in inbound {
            self.admit_socket_packet(packet, &mut summary);
        }
        for packet in outbound {
            self.admit_outbound_packet(packet, &mut summary);
        }

        self.finish_aead_output_turn(summary, sink, limit)
    }

    pub(crate) fn run_aead_raw_ingress_turn<I, O, R>(
        &mut self,
        inbound: I,
        router: &mut R,
        outbound: O,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        I: IntoIterator<Item = PacketMover2RawIngress>,
        O: IntoIterator<Item = OutboundPacket>,
        R: PacketMover2IngressRouter,
    {
        self.reset_turn_buffers();

        let summary = self.admit_raw_ingress_turn(inbound, router, outbound);
        self.finish_aead_turn(summary, limit)
    }

    pub(crate) fn run_aead_raw_ingress_output_turn<I, O, R, S>(
        &mut self,
        inbound: I,
        router: &mut R,
        outbound: O,
        sink: &mut S,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        I: IntoIterator<Item = PacketMover2RawIngress>,
        O: IntoIterator<Item = OutboundPacket>,
        R: PacketMover2IngressRouter,
        S: PacketMover2OutputSink,
    {
        self.reset_turn_buffers();

        let summary = self.admit_raw_ingress_turn(inbound, router, outbound);
        self.finish_aead_output_turn(summary, sink, limit)
    }

    pub(crate) fn pump_aead_output_turn<RI, O, R, S>(
        &mut self,
        raw_ingress: &mut RI,
        router: &mut R,
        raw_ingress_limit: usize,
        outbound: &mut O,
        outbound_limit: usize,
        sink: &mut S,
        crypto_limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        RI: PacketMover2RawIngressSource,
        O: PacketMover2OutboundSource,
        R: PacketMover2IngressRouter,
        S: PacketMover2OutputSink,
    {
        self.reset_turn_buffers();

        let mut summary = PacketMover2RuntimeSummary::default();
        raw_ingress.drain_raw_ingress(raw_ingress_limit, |packet| {
            self.admit_raw_ingress_packet(packet, router, &mut summary);
        });
        outbound.drain_outbound(outbound_limit, |packet| {
            self.admit_outbound_packet(packet, &mut summary);
        });

        self.finish_aead_output_turn(summary, sink, crypto_limit)
    }

    async fn finish_aead_live_node_output_turn<Resolver, Transports>(
        &mut self,
        summary: PacketMover2RuntimeSummary,
        routes: &mut PacketMover2LiveRouteTable,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        endpoint_resolver: Resolver,
        transports: &Transports,
        crypto_limit: usize,
    ) -> PacketMover2LiveNodeTurn
    where
        Resolver: PacketMover2EndpointIdentityResolver,
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        let summary = self.collect_live_session_outputs(summary, routes, crypto_limit);
        let mut transport_output = PacketMover2TransportSendPlanOutput::new();
        let mut report = {
            let tun_output = PacketMover2TunTxOutput::new(tun_tx);
            let endpoint_output =
                PacketMover2EndpointEventOutput::new(endpoint_tx, endpoint_resolver);
            let mut sink =
                PacketMover2LiveOutputSink::new(tun_output, endpoint_output, &mut transport_output);
            let turn = self.send_collected_outputs(summary, &mut sink);
            PacketMover2LiveNodeTurn::from_runtime_turn(&turn)
        };

        let plans = transport_output.take_plans();
        report.transport_planned = plans.len();
        let dropped_before = report.output_drops.len();
        report.transport_sent =
            send_packet_mover2_transport_plans(transports, plans, &mut report.output_drops).await;
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
        report
    }

    async fn pump_aead_live_node_route_table_turn<RI, Resolver, Transports>(
        &mut self,
        raw_ingress: &mut RI,
        routes: &mut PacketMover2LiveRouteTable,
        raw_ingress_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
        deferred_endpoint_commands: &mut Vec<NodeEndpointCommand>,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        endpoint_resolver: Resolver,
        transports: &Transports,
        crypto_limit: usize,
    ) -> PacketMover2LiveNodeTurn
    where
        RI: PacketMover2RawIngressSource,
        Resolver: PacketMover2EndpointIdentityResolver,
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        self.reset_turn_buffers();

        let mut summary = PacketMover2RuntimeSummary::default();
        raw_ingress.drain_raw_ingress(raw_ingress_limit, |packet| {
            self.admit_raw_ingress_packet(packet, routes, &mut summary);
        });

        let outbound_limit = endpoint_limit.saturating_add(tun_limit);
        let (endpoint_drops, deferred, tun_drops) = {
            let mut outbound_source = PacketMover2RouteTableOutboundSource::new(
                endpoint_priority_rx,
                endpoint_bulk_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                routes,
            );
            outbound_source.drain_outbound(outbound_limit, |packet| {
                self.admit_outbound_packet(packet, &mut summary);
            });
            (
                outbound_source.take_endpoint_command_drops(),
                outbound_source.take_endpoint_deferred_commands(),
                outbound_source.take_tun_outbound_drops(),
            )
        };

        let mut report = self
            .finish_aead_live_node_output_turn(
                summary,
                routes,
                tun_tx,
                endpoint_tx,
                endpoint_resolver,
                transports,
                crypto_limit,
            )
            .await;
        report.set_endpoint_command_drops(endpoint_drops);
        report.set_endpoint_deferred_commands(deferred.len());
        deferred_endpoint_commands.extend(deferred);
        report.set_tun_outbound_drops(tun_drops);
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
        self.drops.clear();
        self.raw_ingress_drops.clear();
        self.output_drops.clear();
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

        let source_path = packet.path.clone();
        let mut socket_packet = SocketPacket::new(
            route.owner,
            route.generation,
            header.counter(),
            route.class,
            route.output,
            packet.payload,
        )
        .with_source_path(source_path);
        if let Some(tick) = packet.activity_tick {
            socket_packet = socket_packet.with_activity_tick(tick);
        }
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

    fn finish_aead_turn(
        &mut self,
        summary: PacketMover2RuntimeSummary,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_> {
        let summary = self.collect_aead_outputs(summary, limit);

        PacketMover2RuntimeTurn {
            summary,
            raw_ingress_drops: &self.raw_ingress_drops,
            output_drops: &self.output_drops,
            outputs: &self.outputs,
            drops: &self.drops,
        }
    }

    fn finish_aead_output_turn<S>(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        sink: &mut S,
        limit: usize,
    ) -> PacketMover2RuntimeTurn<'_>
    where
        S: PacketMover2OutputSink,
    {
        summary = self.collect_aead_outputs(summary, limit);
        self.send_collected_outputs(summary, sink)
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
        let sent = sink.send_batch(self.outputs.drain(..), &mut self.output_drops);
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
        let outputs = std::mem::take(&mut self.outputs);
        let dropped_before = self.output_drops.len();
        let admitted_before = summary.inbound_admitted;
        for output in outputs {
            match output.target {
                OutputTarget::SessionIngress { local_addr } => {
                    match packet_mover2_session_ingress_from_output(&output, local_addr) {
                        Ok(raw) => self.admit_raw_ingress_packet(raw, router, summary),
                        Err(error) => self.output_drops.push(PacketMover2OutputDrop::from_output(
                            &output,
                            packet_mover2_output_error_from_session_handoff(error),
                        )),
                    }
                }
                _ => self.outputs.push(output),
            }
        }
        summary.outputs = self.outputs.len();
        summary.outputs_dropped = summary
            .outputs_dropped
            .saturating_add(self.output_drops.len().saturating_sub(dropped_before));
        summary.inbound_admitted.saturating_sub(admitted_before)
    }

    fn collect_live_session_outputs<R>(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        router: &mut R,
        crypto_limit: usize,
    ) -> PacketMover2RuntimeSummary
    where
        R: PacketMover2IngressRouter,
    {
        let mut remaining = crypto_limit;
        loop {
            let dispatched_before = summary.dispatched;
            summary = self.collect_aead_outputs(summary, remaining);
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

    fn collect_aead_outputs(
        &mut self,
        mut summary: PacketMover2RuntimeSummary,
        limit: usize,
    ) -> PacketMover2RuntimeSummary {
        let PacketMoverTurn {
            dispatched,
            retired,
            drops,
        } = self.mover.run_aead_available_with_scratch(
            limit,
            &mut self.open_work,
            &mut self.seal_work,
        );
        summary.dispatched = summary.dispatched.saturating_add(dispatched);
        self.drops.extend(drops);

        for packet in retired {
            match packet {
                RetiredPacket::Output(output) => self.outputs.push(output),
                RetiredPacket::Outbound(packet) => self.admit_outbound_packet(packet, &mut summary),
                RetiredPacket::Drop(_) => {}
            }
        }

        summary.outputs = self.outputs.len();
        summary.drops = self.drops.len();
        summary
    }
}
