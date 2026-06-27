#[derive(Debug)]
pub(crate) struct PacketMover2TurnDriver<W = CopyCryptoWorker> {
    mover: PacketMover2<W>,
    open_work: Vec<CryptoWork>,
    seal_work: Vec<OutboundCryptoWork>,
    raw_ingress_drops: Vec<PacketMover2RawIngressDrop>,
    output_drops: Vec<PacketMover2OutputDrop>,
    outputs: Vec<PacketOutput>,
    drops: Vec<PacketDrop>,
    fmp_ingress_receipts: Vec<PacketMover2FmpIngressReceipt>,
    fmp_legacy_ingress: Vec<PacketMover2FmpLegacyIngress>,
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
            fmp_ingress_receipts: Vec::new(),
            fmp_legacy_ingress: Vec::new(),
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
        report.set_fmp_ingress_receipts(std::mem::take(&mut self.fmp_ingress_receipts));
        report.set_fmp_legacy_ingress(std::mem::take(&mut self.fmp_legacy_ingress));

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
        self.pump_aead_live_node_route_table_turn_with_firsts(
            raw_ingress,
            routes,
            raw_ingress_limit,
            endpoint_priority_rx,
            endpoint_bulk_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            PacketMover2LiveOutboundFirsts::default(),
            deferred_endpoint_commands,
            tun_tx,
            endpoint_tx,
            endpoint_resolver,
            transports,
            crypto_limit,
        )
        .await
    }

    async fn pump_aead_live_node_route_table_turn_with_firsts<RI, Resolver, Transports>(
        &mut self,
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
        let (endpoint_drops, endpoint_drained, deferred, tun_drops, tun_drained) = {
            let mut outbound_source = PacketMover2RouteTableOutboundSource::new(
                endpoint_priority_rx,
                endpoint_bulk_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                routes,
            )
            .with_firsts(outbound_firsts);
            outbound_source.drain_outbound(outbound_limit, |packet| {
                self.admit_outbound_packet(packet, &mut summary);
            });
            (
                outbound_source.take_endpoint_command_drops(),
                outbound_source.endpoint_drained(),
                outbound_source.take_endpoint_deferred_commands(),
                outbound_source.take_tun_outbound_drops(),
                outbound_source.tun_drained(),
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
        report.set_endpoint_source_drained(endpoint_drained);
        report.set_endpoint_deferred_commands(deferred.len());
        deferred_endpoint_commands.extend(deferred);
        report.set_tun_outbound_drops(tun_drops);
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
        self.drops.clear();
        self.raw_ingress_drops.clear();
        self.output_drops.clear();
        self.fmp_ingress_receipts.clear();
        self.fmp_legacy_ingress.clear();
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
                        Ok(raw) => {
                            if let Some(receipt) = PacketMover2FmpIngressReceipt::from_output(&output)
                            {
                                self.fmp_ingress_receipts.push(receipt);
                            }
                            self.admit_raw_ingress_packet(raw, router, summary);
                        }
                        Err(PacketMover2SessionHandoffError::NoRoute) => {
                            match PacketMover2FmpLegacyIngress::from_output(output) {
                                Ok(ingress) => self.fmp_legacy_ingress.push(ingress),
                                Err(output) => {
                                    self.output_drops.push(PacketMover2OutputDrop::from_output(
                                        &output,
                                        PacketMover2OutputError::NoRoute,
                                    ));
                                }
                            }
                        }
                        Err(error) => {
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
