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
pub(crate) struct PacketMover2LiveNode {
    driver: PacketMover2TurnDriver,
    crypto_worker: PacketMover2AeadWorkerPool,
    routes: PacketMover2LiveRouteTable,
    deferred_endpoint_commands: Vec<NodeEndpointCommand>,
    deferred_tun_packets: Vec<Vec<u8>>,
    empty_raw_ingress: VecDeque<PacketMover2RawIngress>,
    empty_endpoint_priority_rx: tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
    empty_endpoint_bulk_rx: tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
    empty_tun_outbound_rx: TunOutboundRx,
}

impl PacketMover2LiveNode {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        let (_, empty_endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_, empty_endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (_, empty_tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        let worker_capacity = config.total_capacity().max(1);
        Self {
            driver: PacketMover2TurnDriver::new(config),
            crypto_worker: PacketMover2AeadWorkerPool::new(
                packet_mover2_aead_worker_count(),
                worker_capacity,
            ),
            routes: PacketMover2LiveRouteTable::default(),
            deferred_endpoint_commands: Vec::new(),
            deferred_tun_packets: Vec::new(),
            empty_raw_ingress: VecDeque::new(),
            empty_endpoint_priority_rx,
            empty_endpoint_bulk_rx,
            empty_tun_outbound_rx,
        }
    }

    pub(crate) fn completion_notify(&self) -> Arc<tokio::sync::Notify> {
        self.crypto_worker.completion_notify()
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

    pub(crate) fn has_owner(&self, owner: OwnerId) -> bool {
        self.driver.has_owner(owner)
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

    pub(crate) fn install_owner_fsp_session(
        &mut self,
        owner: OwnerId,
        config: OwnerConfig,
        keys: OwnerCryptoKeys,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        if !owner_state.install_fsp_session(config, keys) {
            return Err(PacketMover2LiveOwnerError::OwnerMismatch);
        }
        Ok(())
    }

    pub(crate) fn apply_owner_live_config(
        &mut self,
        owner: OwnerId,
        config: OwnerConfig,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        owner_state.apply_live_config(config);
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
        if !owner_state.set_fsp_coords_warmup(remaining, prefix) {
            return Err(PacketMover2LiveOwnerError::OwnerMismatch);
        }
        Ok(())
    }

    pub(crate) fn set_owner_fsp_epoch(
        &mut self,
        owner: OwnerId,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        if !owner_state.set_fsp_epoch(current_k_bit, previous_draining_k_bit) {
            return Err(PacketMover2LiveOwnerError::OwnerMismatch);
        }
        Ok(())
    }

    pub(crate) fn install_owner_fsp_pending_receive_epoch(
        &mut self,
        owner: OwnerId,
        pending_k_bit: bool,
        open: AeadKey,
    ) -> Result<(), PacketMover2LiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        };
        if !owner_state.install_fsp_pending_receive_epoch(pending_k_bit, open) {
            return Err(PacketMover2LiveOwnerError::OwnerMismatch);
        }
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

    pub(crate) fn owner_active_path(
        &self,
        owner: OwnerId,
    ) -> Result<Option<TransportPath>, PacketMover2LiveOwnerError> {
        if !self.driver.has_owner(owner) {
            return Err(PacketMover2LiveOwnerError::UnknownOwner);
        }
        Ok(self.driver.owner_active_path(owner))
    }

    pub(crate) fn fsp_owner_activity(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FspOwnerActivity> {
        self.driver
            .owner_fsp_activity(OwnerId::fsp_node(*node_addr))
    }

    pub(crate) fn fsp_mmp_snapshot(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FspMmpSnapshot> {
        self.driver
            .owner_fsp_mmp_snapshot(OwnerId::fsp_node(*node_addr))
    }

    pub(crate) fn fsp_owner_send_context(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FspSendContext> {
        self.driver
            .owner_fsp_send_context(OwnerId::fsp_node(*node_addr))
    }

    pub(crate) fn fmp_owner_send_context(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FmpSendContext> {
        self.driver
            .owner_fmp_send_context(OwnerId::fmp_node(*node_addr))
    }

    pub(crate) fn fmp_link_metrics(
        &self,
        node_addr: &NodeAddr,
        now: std::time::Instant,
    ) -> Option<PacketMover2FmpLinkMetrics> {
        self.driver
            .owner_fmp_link_metrics(OwnerId::fmp_node(*node_addr), now)
    }

    pub(crate) fn fmp_link_cost(&self, node_addr: &NodeAddr) -> Option<f64> {
        self.driver
            .owner_fmp_link_cost(OwnerId::fmp_node(*node_addr))
    }

    pub(crate) fn fmp_has_srtt(&self, node_addr: &NodeAddr) -> bool {
        self.driver
            .owner_fmp_has_srtt(OwnerId::fmp_node(*node_addr))
    }

    pub(crate) fn record_authenticated_fmp_mmp_receive(
        &mut self,
        node_addr: &NodeAddr,
        counter: u64,
        timestamp_ms: u32,
        packet_len: usize,
        ce_flag: bool,
        spin_bit: bool,
        now: std::time::Instant,
    ) -> Result<Option<std::time::Duration>, PacketMover2FmpMmpSkip> {
        let owner = OwnerId::fmp_node(*node_addr);
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2FmpMmpSkip::UnknownOwner);
        };
        owner_state.record_authenticated_fmp_receive(
            counter,
            timestamp_ms,
            packet_len,
            ce_flag,
            spin_bit,
            now,
        )
    }

    pub(crate) fn record_fmp_mmp_send_result(
        &mut self,
        node_addr: &NodeAddr,
        counter: u64,
        timestamp_ms: u32,
        bytes_sent: usize,
    ) -> Result<(), PacketMover2FmpMmpSkip> {
        let owner = OwnerId::fmp_node(*node_addr);
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2FmpMmpSkip::UnknownOwner);
        };
        owner_state.record_fmp_send_result(counter, timestamp_ms, bytes_sent)
    }

    pub(crate) fn process_fmp_mmp_receiver_report(
        &mut self,
        node_addr: &NodeAddr,
        rr: &crate::mmp::report::ReceiverReport,
        now_ms: u64,
        now: std::time::Instant,
    ) -> Result<PacketMover2FmpReceiverReportResult, PacketMover2FmpMmpSkip> {
        let owner = OwnerId::fmp_node(*node_addr);
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(PacketMover2FmpMmpSkip::UnknownOwner);
        };
        owner_state.process_fmp_mmp_receiver_report(rr, now_ms, now)
    }

    pub(crate) fn collect_fmp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> PacketMover2FmpMmpReportBatch {
        self.driver.collect_fmp_mmp_reports(now)
    }

    pub(crate) fn collect_fsp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> PacketMover2FspMmpReportBatch {
        self.driver.collect_fsp_mmp_reports(now)
    }

    pub(crate) fn record_fsp_mmp_send_result(
        &mut self,
        dest_addr: NodeAddr,
        success: bool,
    ) -> Option<PacketMover2FspMmpReportingResumed> {
        self.driver
            .record_fsp_mmp_send_result(OwnerId::fsp_node(dest_addr), success)
    }

    pub(crate) fn seed_fsp_path_mtu(
        &mut self,
        dest_addr: NodeAddr,
        path_mtu: u16,
    ) -> Result<(), PacketMover2FspMmpSkip> {
        self.driver
            .seed_fsp_path_mtu(OwnerId::fsp_node(dest_addr), path_mtu)
    }

    pub(crate) fn process_fsp_mmp_receiver_report(
        &mut self,
        source_addr: NodeAddr,
        rr: &crate::mmp::report::ReceiverReport,
        last_outbound_next_hop: Option<NodeAddr>,
        now_ms: u64,
        now: std::time::Instant,
        min_loss_sample: u64,
    ) -> Result<PacketMover2FspReceiverReportResult, PacketMover2FspMmpSkip> {
        self.driver.process_fsp_mmp_receiver_report(
            OwnerId::fsp_node(source_addr),
            rr,
            last_outbound_next_hop,
            now_ms,
            now,
            min_loss_sample,
        )
    }

    pub(crate) fn apply_fsp_path_mtu_signal(
        &mut self,
        dest_addr: NodeAddr,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<PacketMover2FspPathMtuApplyResult, PacketMover2FspMmpSkip> {
        self.driver
            .apply_fsp_path_mtu_signal(OwnerId::fsp_node(dest_addr), path_mtu, now)
    }

    pub(crate) fn min_fsp_rx_age_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
    ) -> Option<u64> {
        self.driver.min_fsp_rx_age_for_next_hop(next_hop, now_ms)
    }

    pub(crate) fn min_fsp_data_rx_age_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
    ) -> Option<u64> {
        self.driver
            .min_fsp_data_rx_age_for_next_hop(next_hop, now_ms)
    }

    pub(crate) fn any_fsp_recent_outbound_without_inbound_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
        timeout_ms: u64,
    ) -> bool {
        self.driver
            .any_fsp_recent_outbound_without_inbound_for_next_hop(next_hop, now_ms, timeout_ms)
    }

    pub(crate) fn record_authenticated_fsp_session(
        &mut self,
        source_addr: NodeAddr,
        previous_hop: NodeAddr,
        msg_type: u8,
        body_len: usize,
        sync: FspReceiveSync,
        activity_tick: Option<ActivityTick>,
        now: std::time::Instant,
    ) -> Option<bool> {
        self.driver.record_authenticated_fsp_session(
            OwnerId::fsp_node(source_addr),
            previous_hop,
            msg_type,
            body_len,
            sync,
            activity_tick,
            now,
        )
    }

    pub(crate) fn record_fsp_decrypt_failure(&mut self, source_addr: NodeAddr) -> Option<u32> {
        self.driver
            .record_fsp_decrypt_failure(OwnerId::fsp_node(source_addr))
    }

    pub(crate) fn record_fsp_data_sent(
        &mut self,
        dest_addr: NodeAddr,
        next_hop: NodeAddr,
        bytes: usize,
        tick: ActivityTick,
    ) -> bool {
        self.driver
            .record_fsp_data_sent(OwnerId::fsp_node(dest_addr), next_hop, bytes, tick)
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

    pub(crate) fn take_deferred_endpoint_commands(&mut self) -> Vec<NodeEndpointCommand> {
        std::mem::take(&mut self.deferred_endpoint_commands)
    }

    pub(crate) fn take_deferred_tun_packets(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.deferred_tun_packets)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn pump_turn_with_firsts_and_transport_worker<RI, Transports>(
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
        transports: &Transports,
        crypto_limit: usize,
        transport_send_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
        RI: PacketMover2RawIngressSource,
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        self.pump_turn_with_transport_worker_inner(
            raw_ingress,
            raw_ingress_limit,
            outbound_firsts,
            endpoint_priority_rx,
            endpoint_bulk_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            tun_tx,
            endpoint_tx,
            transports,
            crypto_limit,
            transport_send_worker,
        )
        .await
    }

    async fn pump_turn_with_transport_worker_inner<RI, Transports>(
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
        transports: &Transports,
        crypto_limit: usize,
        transport_send_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
        RI: PacketMover2RawIngressSource,
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        let _turn_timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2LiveTurn);
        let summary = self
            .driver
            .start_aead_completion_turn(&mut self.crypto_worker, crypto_limit);
        self.driver
            .pump_aead_live_node_route_table_executor_turn_after_completion_with_firsts(
                summary,
                &mut self.crypto_worker,
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
                &mut self.deferred_tun_packets,
                tun_tx,
                endpoint_tx,
                transports,
                crypto_limit,
                transport_send_worker,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn pump_outbound_firsts_with_transport_worker<Transports>(
        &mut self,
        outbound_firsts: PacketMover2LiveOutboundFirsts,
        endpoint_limit: usize,
        tun_limit: usize,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        transports: &Transports,
        crypto_limit: usize,
        transport_send_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        self.pump_outbound_firsts_with_transport_worker_inner(
            outbound_firsts,
            endpoint_limit,
            tun_limit,
            tun_tx,
            endpoint_tx,
            transports,
            crypto_limit,
            transport_send_worker,
        )
        .await
    }

    async fn pump_outbound_firsts_with_transport_worker_inner<Transports>(
        &mut self,
        outbound_firsts: PacketMover2LiveOutboundFirsts,
        endpoint_limit: usize,
        tun_limit: usize,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        transports: &Transports,
        crypto_limit: usize,
        transport_send_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        let Self {
            driver,
            crypto_worker,
            routes,
            deferred_endpoint_commands,
            deferred_tun_packets,
            empty_raw_ingress,
            empty_endpoint_priority_rx,
            empty_endpoint_bulk_rx,
            empty_tun_outbound_rx,
            ..
        } = self;
        empty_raw_ingress.clear();

        let _turn_timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2LiveTurn);
        let summary = driver.start_aead_completion_turn(crypto_worker, crypto_limit);
        driver
            .pump_aead_live_node_route_table_executor_turn_after_completion_with_firsts(
                summary,
                crypto_worker,
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
                deferred_tun_packets,
                tun_tx,
                endpoint_tx,
                transports,
                crypto_limit,
                transport_send_worker,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn pump_packet_rx_turn_with_firsts_and_transport_worker<Transports>(
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
        transports: &Transports,
        crypto_limit: usize,
        transport_send_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
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
            .pump_turn_with_firsts_and_transport_worker(
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
                transports,
                crypto_limit,
                transport_send_worker,
            )
            .await;
        turn.set_fmp_control_ingress(raw_ingress.take_control_ingress());
        turn
    }
}

fn packet_mover2_aead_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
}
