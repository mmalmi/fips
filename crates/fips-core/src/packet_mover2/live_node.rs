#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2LiveFmpIngressRoute {
    transport_id: TransportId,
    receiver_idx: u32,
    route: PacketMover2IngressRoute,
}

impl PacketMover2LiveFmpIngressRoute {
    pub(crate) fn new(
        transport_id: TransportId,
        receiver_idx: u32,
        route: PacketMover2IngressRoute,
    ) -> Self {
        Self {
            transport_id,
            receiver_idx,
            route,
        }
    }

    fn owner(&self) -> OwnerId {
        self.route.owner
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2LiveFspIngressRoute {
    source_addr: NodeAddr,
    route: PacketMover2IngressRoute,
}

impl PacketMover2LiveFspIngressRoute {
    pub(crate) fn new(source_addr: NodeAddr, route: PacketMover2IngressRoute) -> Self {
        Self { source_addr, route }
    }

    fn owner(&self) -> OwnerId {
        self.route.owner
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2LiveTunRoute {
    dest_addr: NodeAddr,
    route: PacketMover2TunDestinationRoute,
}

impl PacketMover2LiveTunRoute {
    pub(crate) fn new(dest_addr: NodeAddr, route: PacketMover2TunDestinationRoute) -> Self {
        Self { dest_addr, route }
    }

    fn owner(&self) -> OwnerId {
        self.route.owner()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2LiveEndpointRoute {
    dest_addr: NodeAddr,
    route: PacketMover2EndpointCommandRoute,
}

impl PacketMover2LiveEndpointRoute {
    pub(crate) fn new(dest_addr: NodeAddr, route: PacketMover2EndpointCommandRoute) -> Self {
        Self { dest_addr, route }
    }

    fn owner(&self) -> OwnerId {
        self.route.owner()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PacketMover2LiveOwnerRoutes {
    fmp_ingress: Vec<PacketMover2LiveFmpIngressRoute>,
    fsp_ingress: Vec<PacketMover2LiveFspIngressRoute>,
    tun_destinations: Vec<PacketMover2LiveTunRoute>,
    endpoint_destinations: Vec<PacketMover2LiveEndpointRoute>,
}

impl PacketMover2LiveOwnerRoutes {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push_fmp_ingress(&mut self, route: PacketMover2LiveFmpIngressRoute) {
        self.fmp_ingress.push(route);
    }

    pub(crate) fn push_fsp_ingress(&mut self, route: PacketMover2LiveFspIngressRoute) {
        self.fsp_ingress.push(route);
    }

    pub(crate) fn push_tun_destination(&mut self, route: PacketMover2LiveTunRoute) {
        self.tun_destinations.push(route);
    }

    pub(crate) fn push_endpoint_destination(&mut self, route: PacketMover2LiveEndpointRoute) {
        self.endpoint_destinations.push(route);
    }

    fn len(&self) -> usize {
        self.fmp_ingress.len()
            + self.fsp_ingress.len()
            + self.tun_destinations.len()
            + self.endpoint_destinations.len()
    }

    fn has_owner_mismatch(&self, owner: OwnerId) -> bool {
        self.fmp_ingress.iter().any(|route| route.owner() != owner)
            || self.fsp_ingress.iter().any(|route| route.owner() != owner)
            || self
                .tun_destinations
                .iter()
                .any(|route| route.owner() != owner)
            || self
                .endpoint_destinations
                .iter()
                .any(|route| route.owner() != owner)
    }

    fn apply_to(self, routes: &mut PacketMover2LiveRouteTable) {
        for route in self.fmp_ingress {
            routes.register_fmp(route.transport_id, route.receiver_idx, route.route);
        }
        for route in self.fsp_ingress {
            routes.register_fsp(route.source_addr, route.route);
        }
        for route in self.tun_destinations {
            routes.register_tun_destination(route.dest_addr, route.route);
        }
        for route in self.endpoint_destinations {
            routes.register_endpoint_destination(route.dest_addr, route.route);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2LiveOwnerError {
    UnknownOwner,
    OwnerMismatch,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PacketMover2LiveOwnerRouteSummary {
    owner_removed: bool,
    routes_removed: usize,
    routes_added: usize,
}

impl PacketMover2LiveOwnerRouteSummary {
    pub(crate) fn owner_removed(&self) -> bool {
        self.owner_removed
    }

    pub(crate) fn routes_removed(&self) -> usize {
        self.routes_removed
    }

    pub(crate) fn routes_added(&self) -> usize {
        self.routes_added
    }
}

#[derive(Debug, Default)]
pub(crate) struct PacketMover2LiveTurnFirsts {
    raw_packet: Option<ReceivedPacket>,
    endpoint_priority: Option<NodeEndpointCommand>,
    endpoint_bulk: Option<NodeEndpointCommand>,
    tun_packet: Option<Vec<u8>>,
}

impl PacketMover2LiveTurnFirsts {
    pub(crate) fn with_raw_packet(mut self, packet: Option<ReceivedPacket>) -> Self {
        self.raw_packet = packet;
        self
    }

    pub(crate) fn with_endpoint_priority(mut self, command: Option<NodeEndpointCommand>) -> Self {
        self.endpoint_priority = command;
        self
    }

    pub(crate) fn with_endpoint_bulk(mut self, command: Option<NodeEndpointCommand>) -> Self {
        self.endpoint_bulk = command;
        self
    }

    pub(crate) fn with_tun_packet(mut self, packet: Option<Vec<u8>>) -> Self {
        self.tun_packet = packet;
        self
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2LiveNode<W = CopyCryptoWorker> {
    driver: PacketMover2TurnDriver<W>,
    routes: PacketMover2LiveRouteTable,
    deferred_endpoint_commands: Vec<NodeEndpointCommand>,
    transport_output: PacketMover2TransportSendPlanOutput,
    empty_raw_ingress: VecDeque<PacketMover2RawIngress>,
    empty_endpoint_priority_rx: tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
    empty_endpoint_bulk_rx: tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
    empty_tun_outbound_rx: TunOutboundRx,
}

impl<W: StatelessCryptoWorker> PacketMover2LiveNode<W> {
    pub(crate) fn new(config: AdmissionConfig, worker: W) -> Self {
        let (_, empty_endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_, empty_endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (_, empty_tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        Self {
            driver: PacketMover2TurnDriver::new(config, worker),
            routes: PacketMover2LiveRouteTable::default(),
            deferred_endpoint_commands: Vec::new(),
            transport_output: PacketMover2TransportSendPlanOutput::new(),
            empty_raw_ingress: VecDeque::new(),
            empty_endpoint_priority_rx,
            empty_endpoint_bulk_rx,
            empty_tun_outbound_rx,
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.driver.register_owner(owner, config);
    }

    pub(crate) fn register_owner_if_missing(
        &mut self,
        owner: OwnerId,
        config: OwnerConfig,
    ) -> bool {
        if self.driver.has_owner(owner) {
            return false;
        }
        self.driver.register_owner(owner, config);
        true
    }

    pub(crate) fn set_owner_crypto_keys(
        &mut self,
        owner: OwnerId,
        keys: OwnerCryptoKeys,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        owner_state.set_crypto_keys(keys);
        Ok(())
    }

    pub(crate) fn set_owner_send_counter_authority(
        &mut self,
        owner: OwnerId,
        authority: crate::noise::SendCounterAuthority,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        owner_state.set_send_counter_authority(authority);
        Ok(())
    }

    pub(crate) fn set_owner_active_path(
        &mut self,
        owner: OwnerId,
        path: TransportPath,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        owner_state.set_active_path(path);
        Ok(())
    }

    pub(crate) fn set_owner_fmp_session_start_ms(
        &mut self,
        owner: OwnerId,
        session_start_ms: u64,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        owner_state.set_fmp_session_start_ms(session_start_ms);
        Ok(())
    }

    pub(crate) fn set_owner_fsp_session_start_ms(
        &mut self,
        owner: OwnerId,
        session_start_ms: u64,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        owner_state.set_fsp_session_start_ms(session_start_ms);
        Ok(())
    }

    pub(crate) fn set_owner_fsp_coords_warmup(
        &mut self,
        owner: OwnerId,
        remaining: u8,
        prefix: Vec<u8>,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        owner_state.set_fsp_coords_warmup(remaining, prefix);
        Ok(())
    }

    pub(crate) fn owner_active_path(
        &self,
        owner: OwnerId,
    ) -> Result<Option<TransportPath>, PacketMover2LiveOwnerError> {
        if !self.driver.has_owner(owner) {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        }
        Ok(self.driver.owner_active_path(owner))
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> PacketMover2LiveOwnerRouteSummary {
        PacketMover2LiveOwnerRouteSummary {
            owner_removed: self.driver.unregister_owner(owner),
            routes_removed: self.routes.unregister_owner(owner),
            routes_added: 0,
        }
    }

    pub(crate) fn replace_owner_routes(
        &mut self,
        owner: OwnerId,
        routes: PacketMover2LiveOwnerRoutes,
    ) -> Result<PacketMover2LiveOwnerRouteSummary, PacketMover2LiveOwnerError> {
        if !self.driver.has_owner(owner) {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        }
        if routes.has_owner_mismatch(owner) {
            return Err(PacketMover2LiveOwnerError::OwnerMismatch);
        }

        let routes_added = routes.len();
        let routes_removed = self.routes.unregister_owner(owner);
        routes.apply_to(&mut self.routes);

        Ok(PacketMover2LiveOwnerRouteSummary {
            owner_removed: false,
            routes_removed,
            routes_added,
        })
    }

    pub(crate) fn rekey_owner(
        &mut self,
        owner: OwnerId,
        generation: u64,
    ) -> Result<usize, PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        owner_state.rekey(generation);
        Ok(self.routes.refresh_owner_generation(owner, generation))
    }

    #[cfg(test)]
    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.driver.owner_mut(owner)
    }

    #[cfg(test)]
    pub(crate) fn routes_mut(&mut self) -> &mut PacketMover2LiveRouteTable {
        &mut self.routes
    }

    pub(crate) fn deferred_endpoint_commands(&self) -> &[NodeEndpointCommand] {
        &self.deferred_endpoint_commands
    }

    pub(crate) fn take_deferred_endpoint_commands(&mut self) -> Vec<NodeEndpointCommand> {
        std::mem::take(&mut self.deferred_endpoint_commands)
    }

    pub(crate) async fn send_outbound_transport<Transports>(
        &mut self,
        outbound: OutboundPacket,
        transports: &Transports,
        crypto_limit: usize,
    ) -> (PacketMover2LiveNodeTurn, Option<PacketOutput>)
    where
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        let mut transport_output = std::mem::take(&mut self.transport_output);
        transport_output.clear();
        let turn = self.driver.run_aead_classified_output_turn(
            std::iter::empty(),
            [outbound],
            &mut transport_output,
            crypto_limit,
        );
        let mut report = PacketMover2LiveNodeTurn::from_runtime_turn(&turn);

        let plans = transport_output.plans();
        report.transport_planned = plans.len();
        let sent_output = if plans.len() == 1 {
            Some(plans[0].output().clone())
        } else {
            None
        };
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
        let sent_output = if report.transport_sent == 1 && report.transport_dropped == 0 {
            sent_output
        } else {
            None
        };
        self.transport_output = transport_output;
        (report, sent_output)
    }

    pub(crate) async fn pump_turn<RI, Resolver, Transports>(
        &mut self,
        raw_ingress: &mut RI,
        raw_ingress_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
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
        self.pump_turn_with_firsts(
            raw_ingress,
            raw_ingress_limit,
            PacketMover2LiveOutboundFirsts::default(),
            endpoint_priority_rx,
            endpoint_bulk_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            tun_tx,
            endpoint_tx,
            endpoint_resolver,
            transports,
            crypto_limit,
        )
        .await
    }

    pub(crate) async fn pump_turn_with_firsts<RI, Resolver, Transports>(
        &mut self,
        raw_ingress: &mut RI,
        raw_ingress_limit: usize,
        outbound_firsts: PacketMover2LiveOutboundFirsts,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
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
        self.driver
            .pump_aead_live_node_route_table_turn_with_firsts(
                raw_ingress,
                &mut self.routes,
                raw_ingress_limit,
                endpoint_priority_rx,
                endpoint_bulk_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                outbound_firsts,
                &mut self.deferred_endpoint_commands,
                tun_tx,
                endpoint_tx,
                endpoint_resolver,
                transports,
                crypto_limit,
            )
            .await
    }

    pub(crate) async fn pump_outbound_firsts<Resolver, Transports>(
        &mut self,
        outbound_firsts: PacketMover2LiveOutboundFirsts,
        endpoint_limit: usize,
        tun_limit: usize,
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
        let Self {
            driver,
            routes,
            deferred_endpoint_commands,
            empty_raw_ingress,
            empty_endpoint_priority_rx,
            empty_endpoint_bulk_rx,
            empty_tun_outbound_rx,
            ..
        } = self;
        empty_raw_ingress.clear();

        driver
            .pump_aead_live_node_route_table_turn_with_firsts(
            empty_raw_ingress,
            routes,
            0,
            empty_endpoint_priority_rx,
            empty_endpoint_bulk_rx,
            endpoint_limit,
            empty_tun_outbound_rx,
            tun_limit,
            outbound_firsts,
            deferred_endpoint_commands,
            tun_tx,
            endpoint_tx,
            endpoint_resolver,
            transports,
            crypto_limit,
        )
            .await
    }

    pub(crate) async fn pump_packet_rx_turn<Resolver, Transports>(
        &mut self,
        packet_rx: &mut PacketRx,
        packet_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
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
        self.pump_packet_rx_turn_with_firsts(
            packet_rx,
            PacketMover2LiveTurnFirsts::default(),
            packet_limit,
            endpoint_priority_rx,
            endpoint_bulk_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            tun_tx,
            endpoint_tx,
            endpoint_resolver,
            transports,
            crypto_limit,
        )
        .await
    }

    pub(crate) async fn pump_packet_rx_turn_with_first<Resolver, Transports>(
        &mut self,
        packet_rx: &mut PacketRx,
        first_packet: Option<ReceivedPacket>,
        packet_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
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
        self.pump_packet_rx_turn_with_firsts(
            packet_rx,
            PacketMover2LiveTurnFirsts::default().with_raw_packet(first_packet),
            packet_limit,
            endpoint_priority_rx,
            endpoint_bulk_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            tun_tx,
            endpoint_tx,
            endpoint_resolver,
            transports,
            crypto_limit,
        )
        .await
    }

    pub(crate) async fn pump_packet_rx_turn_with_firsts<Resolver, Transports>(
        &mut self,
        packet_rx: &mut PacketRx,
        firsts: PacketMover2LiveTurnFirsts,
        packet_limit: usize,
        endpoint_priority_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_bulk_rx: &mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        endpoint_limit: usize,
        tun_outbound_rx: &mut TunOutboundRx,
        tun_limit: usize,
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
        let PacketMover2LiveTurnFirsts {
            raw_packet,
            endpoint_priority,
            endpoint_bulk,
            tun_packet,
        } = firsts;
        let outbound_firsts = PacketMover2LiveOutboundFirsts::default()
            .with_endpoint_priority(endpoint_priority)
            .with_endpoint_bulk(endpoint_bulk)
            .with_tun_packet(tun_packet);
        let mut raw_ingress = PacketMover2FmpPacketRxSource::with_first(packet_rx, raw_packet);
        let mut turn = self
            .pump_turn_with_firsts(
            &mut raw_ingress,
            packet_limit,
            outbound_firsts,
            endpoint_priority_rx,
            endpoint_bulk_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            tun_tx,
            endpoint_tx,
            endpoint_resolver,
            transports,
            crypto_limit,
        )
            .await;
        turn.set_fmp_control_ingress(raw_ingress.take_control_ingress());
        turn
    }
}
