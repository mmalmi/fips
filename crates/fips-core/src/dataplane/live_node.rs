#[derive(Clone, Debug, Eq, PartialEq)]
struct DataplaneLiveFmpIngressRoute {
    transport_id: TransportId,
    receiver_idx: u32,
    route: DataplaneIngressRoute,
}

impl DataplaneLiveFmpIngressRoute {
    fn owner(&self) -> OwnerId {
        self.route.owner
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DataplaneLiveFspIngressRoute {
    source_addr: NodeAddr,
    route: DataplaneIngressRoute,
}

impl DataplaneLiveFspIngressRoute {
    fn owner(&self) -> OwnerId {
        self.route.owner
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DataplaneLiveTunRoute {
    dest_addr: NodeAddr,
    route: DataplaneTunOutboundRoute,
}

impl DataplaneLiveTunRoute {
    fn owner(&self) -> OwnerId {
        self.route.owner()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DataplaneLiveEndpointRoute {
    dest_addr: NodeAddr,
    route: DataplaneEndpointDataRoute,
}

impl DataplaneLiveEndpointRoute {
    fn owner(&self) -> OwnerId {
        self.route.owner()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DataplaneLiveOwnerRoutes {
    fmp_ingress: Vec<DataplaneLiveFmpIngressRoute>,
    fsp_ingress: Vec<DataplaneLiveFspIngressRoute>,
    tun_destinations: Vec<DataplaneLiveTunRoute>,
    endpoint_destinations: Vec<DataplaneLiveEndpointRoute>,
}

impl DataplaneLiveOwnerRoutes {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push_fmp_ingress(
        &mut self,
        transport_id: TransportId,
        receiver_idx: u32,
        route: DataplaneIngressRoute,
    ) {
        self.fmp_ingress.push(DataplaneLiveFmpIngressRoute {
            transport_id,
            receiver_idx,
            route,
        });
    }

    pub(crate) fn push_fsp_ingress(&mut self, source_addr: NodeAddr, route: DataplaneIngressRoute) {
        self.fsp_ingress
            .push(DataplaneLiveFspIngressRoute { source_addr, route });
    }

    pub(crate) fn push_tun_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: DataplaneTunOutboundRoute,
    ) {
        self.tun_destinations
            .push(DataplaneLiveTunRoute { dest_addr, route });
    }

    pub(crate) fn push_endpoint_destination(
        &mut self,
        dest_addr: NodeAddr,
        route: DataplaneEndpointDataRoute,
    ) {
        self.endpoint_destinations
            .push(DataplaneLiveEndpointRoute { dest_addr, route });
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

    fn apply_to(self, routes: &mut DataplaneLiveRouteTable) {
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
pub(crate) enum DataplaneLiveOwnerError {
    UnknownOwner,
    OwnerMismatch,
}

#[derive(Debug, Default)]
pub(crate) struct DataplaneLiveTurnFirsts {
    pub(crate) raw_packet: Option<ReceivedPacket>,
    pub(crate) fast_ingress: Option<DataplaneFastIngressBatch>,
    pub(crate) endpoint_data_batch: Option<NodeEndpointDataBatch>,
    pub(crate) tun_packet: Option<Vec<u8>>,
    pub(crate) raw_ingress_prefetch: bool,
}

#[derive(Debug)]
pub(crate) struct DataplaneLiveNode {
    driver: DataplaneTurnDriver,
    crypto_worker: DataplaneAeadWorkerPool,
    routes: DataplaneLiveRouteTable,
    fast_ingress_capacity: usize,
    deferred_endpoint_data_batches: Vec<NodeEndpointDataBatch>,
    deferred_tun_packets: Vec<Vec<u8>>,
    deferred_raw_ingress: VecDeque<(DataplaneRawIngress, u8)>,
    empty_raw_ingress: VecDeque<DataplaneRawIngress>,
    direct_fsp_reassembler: DataplaneDirectFspReassembler,
}

pub(crate) struct DataplaneLiveTurnIo<'a> {
    pub(crate) endpoint_data_rx: &'a mut EndpointDataBatchRx,
    pub(crate) endpoint_limit: usize,
    pub(crate) tun_outbound_rx: &'a mut TunOutboundRx,
    pub(crate) tun_limit: usize,
    pub(crate) endpoint_tx: &'a EndpointEventSender,
    pub(crate) transports: &'a HashMap<TransportId, TransportHandle>,
    pub(crate) crypto_limit: usize,
    pub(crate) transport_send_batch_packets: usize,
}

impl DataplaneLiveNode {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        let worker_capacity = config.total_capacity().max(1);
        Self {
            driver: DataplaneTurnDriver::new(config),
            crypto_worker: DataplaneAeadWorkerPool::new(
                dataplane_aead_worker_count(),
                worker_capacity,
            ),
            routes: DataplaneLiveRouteTable::default(),
            fast_ingress_capacity: worker_capacity,
            deferred_endpoint_data_batches: Vec::new(),
            deferred_tun_packets: Vec::new(),
            deferred_raw_ingress: VecDeque::new(),
            empty_raw_ingress: VecDeque::new(),
            direct_fsp_reassembler: DataplaneDirectFspReassembler::default(),
        }
    }

    pub(crate) fn completion_notify(&self) -> Arc<tokio::sync::Notify> {
        self.crypto_worker.completion_notify()
    }

    pub(crate) fn has_deferred_raw_ingress(&self) -> bool {
        !self.deferred_raw_ingress.is_empty()
    }

    pub(crate) fn has_runnable_work(&self) -> bool {
        self.driver.has_runnable_work()
            || self.crypto_worker.has_ready_completions()
            || !self.deferred_raw_ingress.is_empty()
    }

    pub(crate) fn attach_established_fast_ingress(
        &self,
        packet_tx: &mut PacketTx,
    ) -> DataplaneFastIngressRx {
        let (sink, rx) = DataplaneEstablishedFastIngressSink::channel(
            self.routes.established_fast_ingress_snapshot(),
            self.fast_ingress_capacity,
        );
        packet_tx.set_fast_ingress_sink(Arc::new(sink));
        rx
    }

    pub(crate) fn set_established_fast_ingress_direct_fsp_sources(
        &self,
        sources: DataplaneDirectFspSources,
    ) {
        self.routes
            .set_established_fast_ingress_direct_fsp_sources(sources);
    }

    #[cfg(test)]
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

    pub(crate) fn fsp_owner_destinations(&self) -> Vec<NodeAddr> {
        self.driver.fsp_owner_destinations()
    }

    pub(crate) fn install_owner_fmp_session_routes(
        &mut self,
        owner: OwnerId,
        config: OwnerConfig,
        keys: OwnerCryptoKeys,
        path: TransportPath,
        routes: DataplaneLiveOwnerRoutes,
    ) -> Result<(), DataplaneLiveOwnerError> {
        if routes.has_owner_mismatch(owner) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneLiveOwnerError::UnknownOwner);
        };
        if !owner_state.install_fmp_session(config, keys) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        owner_state.set_active_path(path);
        self.replace_registered_owner_routes(owner, routes);
        Ok(())
    }

    pub(crate) fn install_owner_fsp_session_routes(
        &mut self,
        owner: OwnerId,
        config: OwnerConfig,
        keys: OwnerCryptoKeys,
        routes: DataplaneLiveOwnerRoutes,
        wrap: Option<DataplaneFspWrapRoute>,
        path: Option<TransportPath>,
    ) -> Result<(), DataplaneLiveOwnerError> {
        if routes.has_owner_mismatch(owner) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneLiveOwnerError::UnknownOwner);
        };
        if !owner_state.install_fsp_session(config, keys) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        if !owner_state.set_fsp_wrap_route(wrap) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        match path {
            Some(path) => owner_state.set_active_path(path),
            None => owner_state.clear_active_path(),
        }

        self.replace_registered_owner_routes(owner, routes);
        Ok(())
    }

    pub(crate) fn set_owner_fsp_coords_warmup(
        &mut self,
        owner: OwnerId,
        remaining: u8,
        prefix: Vec<u8>,
    ) -> Result<(), DataplaneLiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneLiveOwnerError::UnknownOwner);
        };
        if !owner_state.set_fsp_coords_warmup(remaining, prefix) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        Ok(())
    }

    pub(crate) fn set_owner_fsp_epoch(
        &mut self,
        owner: OwnerId,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> Result<(), DataplaneLiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneLiveOwnerError::UnknownOwner);
        };
        if !owner_state.set_fsp_epoch(current_k_bit, previous_draining_k_bit) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        Ok(())
    }

    pub(crate) fn install_owner_fmp_pending_receive_epoch(
        &mut self,
        owner: OwnerId,
        pending_k_bit: bool,
        open: AeadKey,
    ) -> Result<(), DataplaneLiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneLiveOwnerError::UnknownOwner);
        };
        if !owner_state.install_fmp_pending_receive_epoch(pending_k_bit, open) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        Ok(())
    }

    pub(crate) fn install_owner_fsp_pending_receive_epoch(
        &mut self,
        owner: OwnerId,
        pending_k_bit: bool,
        open: AeadKey,
    ) -> Result<(), DataplaneLiveOwnerError> {
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneLiveOwnerError::UnknownOwner);
        };
        if !owner_state.install_fsp_pending_receive_epoch(pending_k_bit, open) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        Ok(())
    }

    pub(crate) fn owner_active_path(
        &self,
        owner: OwnerId,
    ) -> Result<Option<TransportPath>, DataplaneLiveOwnerError> {
        if !self.driver.has_owner(owner) {
            return Err(DataplaneLiveOwnerError::UnknownOwner);
        }
        Ok(self.driver.owner_active_path(owner))
    }

    pub(crate) fn fsp_owner_activity(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<DataplaneFspOwnerActivity> {
        self.driver
            .owner_fsp_activity(OwnerId::fsp_node(*node_addr))
    }

    pub(crate) fn fsp_owner_has_pending_receive_epoch(
        &self,
        node_addr: &NodeAddr,
        received_k_bit: bool,
    ) -> bool {
        self.driver.owner_has_fsp_pending_receive_epoch(
            OwnerId::fsp_node(*node_addr),
            received_k_bit,
        )
    }

    pub(crate) fn fmp_owner_has_pending_receive_epoch(
        &self,
        node_addr: &NodeAddr,
        received_k_bit: bool,
    ) -> bool {
        self.driver.owner_has_fmp_pending_receive_epoch(
            OwnerId::fmp_node(*node_addr),
            received_k_bit,
        )
    }

    pub(crate) fn fsp_mmp_snapshot(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<DataplaneFspMmpSnapshot> {
        self.driver
            .owner_fsp_mmp_snapshot(OwnerId::fsp_node(*node_addr))
    }

    pub(crate) fn fsp_owner_send_context(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<DataplaneFspSendContext> {
        self.driver
            .owner_fsp_send_context(OwnerId::fsp_node(*node_addr))
    }

    pub(crate) fn fsp_owner_next_hop(&self, node_addr: &NodeAddr) -> Option<NodeAddr> {
        self.driver
            .owner_fsp_next_hop(OwnerId::fsp_node(*node_addr))
    }

    pub(crate) fn fmp_owner_send_context(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<DataplaneFmpSendContext> {
        self.driver
            .owner_fmp_send_context(OwnerId::fmp_node(*node_addr))
    }

    pub(crate) fn fmp_link_metrics(
        &self,
        node_addr: &NodeAddr,
        now: std::time::Instant,
    ) -> Option<DataplaneFmpLinkMetrics> {
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
        receive: DataplaneAuthenticatedFmpMmpReceive,
    ) -> Result<Option<std::time::Duration>, DataplaneFmpMmpSkip> {
        let Some(owner_state) = self.driver.owner_mut(receive.owner) else {
            return Err(DataplaneFmpMmpSkip::UnknownOwner);
        };
        owner_state.record_authenticated_fmp_receive(receive)
    }

    pub(crate) fn record_fmp_mmp_send_result(
        &mut self,
        node_addr: &NodeAddr,
        counter: u64,
        timestamp_ms: u32,
        bytes_sent: usize,
    ) {
        let owner = OwnerId::fmp_node(*node_addr);
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return;
        };
        owner_state.record_fmp_send_result(counter, timestamp_ms, bytes_sent)
    }

    pub(crate) fn process_fmp_mmp_receiver_report(
        &mut self,
        node_addr: &NodeAddr,
        rr: &crate::mmp::report::ReceiverReport,
        now_ms: u64,
        now: std::time::Instant,
    ) -> Result<DataplaneFmpReceiverReportResult, DataplaneFmpMmpSkip> {
        let owner = OwnerId::fmp_node(*node_addr);
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneFmpMmpSkip::UnknownOwner);
        };
        owner_state.process_fmp_mmp_receiver_report(rr, now_ms, now)
    }

    pub(crate) fn collect_fmp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> DataplaneFmpMmpReportBatch {
        self.driver.collect_fmp_mmp_reports(now)
    }

    pub(crate) fn collect_fsp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> DataplaneFspMmpReportBatch {
        self.driver.collect_fsp_mmp_reports(now)
    }

    pub(crate) fn record_fsp_mmp_send_result(
        &mut self,
        dest_addr: NodeAddr,
        success: bool,
    ) -> Option<DataplaneFspMmpReportingResumed> {
        self.driver
            .record_fsp_mmp_send_result(OwnerId::fsp_node(dest_addr), success)
    }

    pub(crate) fn seed_fsp_path_mtu(
        &mut self,
        dest_addr: NodeAddr,
        path_mtu: u16,
    ) -> Result<(), DataplaneFspMmpSkip> {
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
    ) -> Result<DataplaneFspReceiverReportResult, DataplaneFspMmpSkip> {
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
    ) -> Result<DataplaneFspPathMtuApplyResult, DataplaneFspMmpSkip> {
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

    #[cfg(test)]
    pub(crate) fn record_authenticated_fsp_session(
        &mut self,
        session: DataplaneAuthenticatedFspSession,
    ) -> Option<bool> {
        self.driver.record_authenticated_fsp_session(session)
    }

    pub(crate) fn record_fsp_decrypt_failure(&mut self, source_addr: NodeAddr) -> Option<u32> {
        self.driver
            .record_fsp_decrypt_failure(OwnerId::fsp_node(source_addr))
    }

    #[cfg(test)]
    pub(crate) fn record_fsp_data_sent(
        &mut self,
        dest_addr: NodeAddr,
        next_hop: NodeAddr,
        bytes: usize,
        tick: ActivityTick,
    ) -> bool {
        self.driver
            .owner_mut(OwnerId::fsp_node(dest_addr))
            .is_some_and(|owner| owner.record_fsp_data_sent(next_hop, bytes, tick))
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) {
        self.driver.unregister_owner(owner);
        self.routes.unregister_owner(owner);
    }

    fn replace_registered_owner_routes(
        &mut self,
        owner: OwnerId,
        routes: DataplaneLiveOwnerRoutes,
    ) {
        self.routes.unregister_owner(owner);
        routes.apply_to(&mut self.routes);
    }

    pub(crate) fn replace_owner_fsp_routes(
        &mut self,
        owner: OwnerId,
        routes: DataplaneLiveOwnerRoutes,
        wrap: Option<DataplaneFspWrapRoute>,
        path: Option<TransportPath>,
    ) -> Result<(), DataplaneLiveOwnerError> {
        if routes.has_owner_mismatch(owner) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneLiveOwnerError::UnknownOwner);
        };
        if !owner_state.set_fsp_wrap_route(wrap) {
            return Err(DataplaneLiveOwnerError::OwnerMismatch);
        }
        match path {
            Some(path) => owner_state.set_active_path(path),
            None => owner_state.clear_active_path(),
        }

        self.replace_registered_owner_routes(owner, routes);
        Ok(())
    }

    pub(crate) fn take_deferred_endpoint_data_batches(
        &mut self,
    ) -> Vec<NodeEndpointDataBatch> {
        std::mem::take(&mut self.deferred_endpoint_data_batches)
    }

    pub(crate) fn take_deferred_tun_packets(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.deferred_tun_packets)
    }

    pub(crate) async fn pump_turn_with_firsts_and_transport_batch<RI>(
        &mut self,
        fast_ingress: Option<DataplaneFastIngressBatch>,
        raw_ingress: &mut RI,
        raw_ingress_limit: usize,
        outbound_firsts: DataplaneLiveOutboundFirsts,
        io: DataplaneLiveTurnIo<'_>,
    ) -> DataplaneLiveNodeTurn
    where
        RI: DataplaneRawIngressSource,
    {
        let DataplaneLiveTurnIo {
            endpoint_data_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            endpoint_tx,
            transports,
            crypto_limit,
            transport_send_batch_packets,
        } = io;
        let _turn_timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneLiveTurn);
        self.crypto_worker.record_perf_depths();
        let compact_endpoint_data = endpoint_tx.direct_sink().is_some();
        let summary = self
            .driver
            .start_aead_completion_turn(
                &mut self.crypto_worker,
                crypto_limit,
                compact_endpoint_data,
            );
        let turn = self.driver
            .pump_aead_live_node_route_table_turn_after_completion_with_firsts(
                DataplaneLivePumpRequest {
                    summary,
                    crypto_worker: &mut self.crypto_worker,
                    fast_ingress,
                    raw_ingress,
                    routes: &mut self.routes,
                    raw_ingress_limit,
                    endpoint_data_rx,
                    endpoint_limit,
                    tun_outbound_rx,
                    tun_limit,
                    outbound_firsts,
                    deferred_endpoint_data_batches: &mut self.deferred_endpoint_data_batches,
                    deferred_tun_packets: &mut self.deferred_tun_packets,
                    deferred_raw_ingress: &mut self.deferred_raw_ingress,
                    endpoint_tx,
                    transports,
                    crypto_limit,
                    transport_send_batch_packets,
                },
            )
            .await;
        if !self.deferred_raw_ingress.is_empty() && !turn.fsp_local_session_ingress().is_empty() {
            self.crypto_worker.completion_notify().notify_one();
        }
        if self.has_runnable_work() {
            self.crypto_worker.completion_notify().notify_one();
        }
        record_dataplane_live_turn_perf(&turn);
        turn
    }

    pub(crate) async fn pump_completion_output_turn_with_transport_batch(
        &mut self,
        io: DataplaneLiveTurnIo<'_>,
    ) -> DataplaneLiveNodeTurn {
        let crypto_limit = io.crypto_limit;
        let mut empty_raw_ingress = std::mem::take(&mut self.empty_raw_ingress);
        empty_raw_ingress.clear();
        let raw_ingress_limit = if self.deferred_raw_ingress.is_empty() {
            0
        } else {
            crypto_limit.max(1)
        };
        let turn = self
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut empty_raw_ingress,
                raw_ingress_limit,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_limit: 0,
                    tun_limit: 0,
                    ..io
                },
            )
            .await;
        self.empty_raw_ingress = empty_raw_ingress;
        turn
    }

    pub(crate) async fn pump_packet_rx_turn_with_firsts_direct_fsp_sources_and_transport_batch(
        &mut self,
        packet_rx: &mut PacketRx,
        firsts: DataplaneLiveTurnFirsts,
        packet_limit: usize,
        direct_fsp_sources: DataplaneDirectFspSources,
        io: DataplaneLiveTurnIo<'_>,
    ) -> DataplaneLiveNodeTurn {
        let DataplaneLiveTurnFirsts {
            raw_packet,
            fast_ingress,
            endpoint_data_batch,
            tun_packet,
            raw_ingress_prefetch,
        } = firsts;
        let outbound_firsts = DataplaneLiveOutboundFirsts {
            endpoint_data_batch,
            tun_packet,
            ..Default::default()
        };
        let mut direct_fsp_reassembler = std::mem::take(&mut self.direct_fsp_reassembler);
        let mut raw_ingress =
            DataplaneFmpPacketRxSource::with_first_direct_fsp_sources_and_reassembler(
                packet_rx,
                raw_packet,
                direct_fsp_sources,
                Some(&mut direct_fsp_reassembler),
            );
        if raw_ingress_prefetch && packet_limit > 0 {
            let mut prefetched = std::mem::take(&mut self.empty_raw_ingress);
            prefetched.clear();
            raw_ingress.drain_raw_ingress(packet_limit, |packet| {
                prefetched.push_back(packet);
            });
            let mut turn = self
                .pump_turn_with_firsts_and_transport_batch(
                    fast_ingress,
                    &mut prefetched,
                    packet_limit,
                    outbound_firsts,
                    io,
                )
                .await;
            let control_ingress = raw_ingress.take_control_ingress();
            drop(raw_ingress);
            turn.fmp_control_ingress = control_ingress;
            self.empty_raw_ingress = prefetched;
            self.direct_fsp_reassembler = direct_fsp_reassembler;
            return turn;
        }
        let mut turn = self
            .pump_turn_with_firsts_and_transport_batch(
                fast_ingress,
                &mut raw_ingress,
                packet_limit,
                outbound_firsts,
                io,
            )
            .await;
        let control_ingress = raw_ingress.take_control_ingress();
        drop(raw_ingress);
        turn.fmp_control_ingress = control_ingress;
        self.direct_fsp_reassembler = direct_fsp_reassembler;
        turn
    }
}

fn dataplane_aead_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
}

fn record_dataplane_live_turn_perf(turn: &DataplaneLiveNodeTurn) {
    if !crate::perf_profile::enabled() {
        return;
    }
    let summary = turn.summary();
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DataplaneLivePreparedDispatched,
        summary.dispatched() as u64,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DataplaneLiveCompletionsDrained,
        summary.completions() as u64,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DataplaneLiveRetiredOutputs,
        summary.outputs() as u64,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DataplaneLiveRetiredDrops,
        summary.drops() as u64,
    );
    for drop in turn.drops() {
        let event = match drop.reason() {
            PacketDropReason::Admission(reason) => {
                let reason_event = match reason {
                    AdmissionDropReason::PriorityFull => {
                        crate::perf_profile::Event::DataplaneLiveDropAdmissionPriorityFull
                    }
                    AdmissionDropReason::BulkFull => {
                        crate::perf_profile::Event::DataplaneLiveDropAdmissionBulkFull
                    }
                };
                crate::perf_profile::record_event(reason_event);
                crate::perf_profile::record_event(dataplane_live_admission_source_event(
                    drop, reason,
                ));
                crate::perf_profile::Event::DataplaneLiveDropAdmission
            }
            PacketDropReason::UnknownOwner => {
                crate::perf_profile::Event::DataplaneLiveDropUnknownOwner
            }
            PacketDropReason::Replay => crate::perf_profile::Event::DataplaneLiveDropReplay,
            PacketDropReason::OwnerInFlightFull => {
                crate::perf_profile::Event::DataplaneLiveDropOwnerInFlightFull
            }
            PacketDropReason::StaleGeneration => {
                crate::perf_profile::Event::DataplaneLiveDropStaleGeneration
            }
            PacketDropReason::CounterExhausted => {
                crate::perf_profile::Event::DataplaneLiveDropCounterExhausted
            }
            PacketDropReason::StaleCompletionGeneration => {
                crate::perf_profile::Event::DataplaneLiveDropStaleCompletionGeneration
            }
            PacketDropReason::CryptoFailed => {
                crate::perf_profile::Event::DataplaneLiveDropCryptoFailed
            }
        };
        crate::perf_profile::record_event(event);
    }
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DataplaneLiveOutputDrops,
        summary.outputs_dropped() as u64,
    );
}

fn dataplane_live_admission_source_event(
    drop: &PacketDrop,
    reason: AdmissionDropReason,
) -> crate::perf_profile::Event {
    match (drop.counter().is_some(), reason) {
        (true, AdmissionDropReason::PriorityFull) => {
            crate::perf_profile::Event::DataplaneLiveDropAdmissionInboundPriorityFull
        }
        (true, AdmissionDropReason::BulkFull) => {
            crate::perf_profile::Event::DataplaneLiveDropAdmissionInboundBulkFull
        }
        (false, AdmissionDropReason::PriorityFull) => {
            crate::perf_profile::Event::DataplaneLiveDropAdmissionOutboundPriorityFull
        }
        (false, AdmissionDropReason::BulkFull) => {
            crate::perf_profile::Event::DataplaneLiveDropAdmissionOutboundBulkFull
        }
    }
}
