const DATAPLANE_DEFERRED_RAW_INGRESS_MAX_AGE_MS: u64 = 5_000;

type DataplaneDeferredRawIngress = (DataplaneRawIngress, u64);

#[derive(Debug)]
pub(crate) struct DataplaneTurnDriver {
    mover: Dataplane,
    prepared_work: Vec<PreparedCryptoRun>,
    ready_slots: Vec<Arc<CryptoReadySlot>>,
    raw_ingress_drops: Vec<DataplaneRawIngressDrop>,
    output_drops: Vec<DataplaneOutputDrop>,
    outputs: Vec<PacketOutput>,
    output_rewrite_buffer: Vec<PacketOutput>,
    raw_socket_packets: Vec<SocketPacket>,
    retired_outbound_packets: Vec<OutboundPacket>,
    transport_output: DataplaneTransportSendGroups,
    drops: Vec<PacketDrop>,
    fmp_ingress_receipts: Vec<DataplaneFmpIngressReceipt>,
    fmp_link_ingress: Vec<DataplaneFmpLinkIngress>,
    fsp_coord_warmups: Vec<DataplaneFspCoordWarmup>,
    fsp_local_session_ingress: Vec<DataplaneFspLocalSessionIngress>,
    fsp_authenticated_ingress: DataplaneFspAuthenticatedIngress,
}

struct DataplaneLiveAdmissionResult {
    summary: DataplaneRuntimeSummary,
    outbound_buffers: DataplaneRouteTableOutboundBuffers,
    endpoint_drained: usize,
    tun_drained: usize,
}

impl DataplaneLiveAdmissionResult {
    fn has_activity(&self) -> bool {
        self.summary.has_activity()
            || self.endpoint_drained > 0
            || self.tun_drained > 0
            || self.outbound_buffers.has_activity()
    }
}

struct DataplaneLiveAdmissionRequest<'a, RI> {
    summary: DataplaneRuntimeSummary,
    fast_ingress: Option<DataplaneFastIngressBatch>,
    raw_ingress: &'a mut RI,
    routes: &'a mut DataplaneLiveRouteTable,
    raw_ingress_limit: usize,
    endpoint_data_rx: &'a mut EndpointDataBatchRx,
    endpoint_limit: usize,
    tun_outbound_rx: &'a mut TunOutboundRx,
    tun_limit: usize,
    outbound_firsts: DataplaneLiveOutboundFirsts,
    deferred_raw_ingress: &'a mut std::collections::VecDeque<DataplaneDeferredRawIngress>,
}

struct DataplaneLiveOutputRequest<'a> {
    summary: DataplaneRuntimeSummary,
    routes: &'a mut DataplaneLiveRouteTable,
    endpoint_tx: &'a EndpointEventSender,
    transports: &'a HashMap<TransportId, TransportHandle>,
    deferred_raw_ingress: &'a mut std::collections::VecDeque<DataplaneDeferredRawIngress>,
    crypto_limit: usize,
    collect_transport_sent_receipts: bool,
    crypto_worker: &'a mut DataplaneAeadWorkerPool,
    transport_send_batch_packets: usize,
}

struct DataplaneLiveFinishRequest<'a> {
    admission: DataplaneLiveAdmissionResult,
    routes: &'a mut DataplaneLiveRouteTable,
    endpoint_tx: &'a EndpointEventSender,
    transports: &'a HashMap<TransportId, TransportHandle>,
    crypto_limit: usize,
    collect_transport_sent_receipts: bool,
    crypto_worker: &'a mut DataplaneAeadWorkerPool,
    transport_send_batch_packets: usize,
    deferred_raw_ingress: &'a mut std::collections::VecDeque<DataplaneDeferredRawIngress>,
    deferred_endpoint_data_batches: &'a mut Vec<NodeEndpointDataBatch>,
    deferred_tun_packets: &'a mut Vec<Vec<u8>>,
}

struct DataplaneLivePumpRequest<'a, RI> {
    summary: DataplaneRuntimeSummary,
    crypto_worker: &'a mut DataplaneAeadWorkerPool,
    fast_ingress: Option<DataplaneFastIngressBatch>,
    raw_ingress: &'a mut RI,
    routes: &'a mut DataplaneLiveRouteTable,
    raw_ingress_limit: usize,
    endpoint_data_rx: &'a mut EndpointDataBatchRx,
    endpoint_limit: usize,
    tun_outbound_rx: &'a mut TunOutboundRx,
    tun_limit: usize,
    outbound_firsts: DataplaneLiveOutboundFirsts,
    deferred_endpoint_data_batches: &'a mut Vec<NodeEndpointDataBatch>,
    deferred_tun_packets: &'a mut Vec<Vec<u8>>,
    deferred_raw_ingress: &'a mut std::collections::VecDeque<DataplaneDeferredRawIngress>,
    endpoint_tx: &'a EndpointEventSender,
    transports: &'a HashMap<TransportId, TransportHandle>,
    crypto_limit: usize,
    transport_send_batch_packets: usize,
}

impl DataplaneTurnDriver {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            mover: Dataplane::new(config),
            prepared_work: Vec::new(),
            ready_slots: Vec::new(),
            raw_ingress_drops: Vec::new(),
            output_drops: Vec::new(),
            outputs: Vec::new(),
            output_rewrite_buffer: Vec::new(),
            raw_socket_packets: Vec::new(),
            retired_outbound_packets: Vec::new(),
            transport_output: DataplaneTransportSendGroups::new(),
            drops: Vec::new(),
            fmp_ingress_receipts: Vec::new(),
            fmp_link_ingress: Vec::new(),
            fsp_coord_warmups: Vec::new(),
            fsp_local_session_ingress: Vec::new(),
            fsp_authenticated_ingress: DataplaneFspAuthenticatedIngress::default(),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.mover.register_owner(owner, config);
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) {
        self.mover.unregister_owner(owner);
    }

    pub(crate) fn has_runnable_work(&self) -> bool {
        self.mover.has_runnable_work()
    }

    pub(crate) fn has_owner(&self, owner: OwnerId) -> bool {
        self.mover.has_owner(owner)
    }

    pub(crate) fn fsp_owner_destinations(&self) -> Vec<NodeAddr> {
        self.mover.fsp_owner_destinations()
    }

    pub(crate) fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.mover.owner_active_path(owner)
    }

    pub(crate) fn owner_fsp_next_hop(&self, owner: OwnerId) -> Option<NodeAddr> {
        self.mover.owner_fsp_next_hop(owner)
    }

    pub(crate) fn owner_fsp_activity(
        &self,
        owner: OwnerId,
    ) -> Option<DataplaneFspOwnerActivity> {
        self.mover.owner_fsp_activity(owner)
    }

    pub(crate) fn owner_has_fsp_pending_receive_epoch(
        &self,
        owner: OwnerId,
        received_k_bit: bool,
    ) -> bool {
        self.mover
            .owner_has_fsp_pending_receive_epoch(owner, received_k_bit)
    }

    pub(crate) fn owner_has_fmp_pending_receive_epoch(
        &self,
        owner: OwnerId,
        received_k_bit: bool,
    ) -> bool {
        self.mover
            .owner_has_fmp_pending_receive_epoch(owner, received_k_bit)
    }

    pub(crate) fn owner_fsp_mmp_snapshot(
        &self,
        owner: OwnerId,
    ) -> Option<DataplaneFspMmpSnapshot> {
        self.mover.owner_fsp_mmp_snapshot(owner)
    }

    pub(crate) fn owner_fsp_send_context(
        &self,
        owner: OwnerId,
    ) -> Option<DataplaneFspSendContext> {
        self.mover.owner_fsp_send_context(owner)
    }

    pub(crate) fn owner_fmp_send_context(
        &self,
        owner: OwnerId,
    ) -> Option<DataplaneFmpSendContext> {
        self.mover.owner_fmp_send_context(owner)
    }

    pub(crate) fn owner_fmp_link_metrics(
        &self,
        owner: OwnerId,
        now: std::time::Instant,
    ) -> Option<DataplaneFmpLinkMetrics> {
        self.mover.owner_fmp_link_metrics(owner, now)
    }

    pub(crate) fn owner_fmp_link_cost(&self, owner: OwnerId) -> Option<f64> {
        self.mover.owner_fmp_link_cost(owner)
    }

    pub(crate) fn owner_fmp_has_srtt(&self, owner: OwnerId) -> bool {
        self.mover.owner_fmp_has_srtt(owner)
    }

    pub(crate) fn collect_fmp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> DataplaneFmpMmpReportBatch {
        self.mover.collect_fmp_mmp_reports(now)
    }

    pub(crate) fn collect_fsp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> DataplaneFspMmpReportBatch {
        self.mover.collect_fsp_mmp_reports(now)
    }

    pub(crate) fn record_fsp_mmp_send_result(
        &mut self,
        owner: OwnerId,
        success: bool,
    ) -> Option<DataplaneFspMmpReportingResumed> {
        self.mover.record_fsp_mmp_send_result(owner, success)
    }

    pub(crate) fn seed_fsp_path_mtu(
        &mut self,
        owner: OwnerId,
        path_mtu: u16,
    ) -> Result<(), DataplaneFspMmpSkip> {
        self.mover.seed_fsp_path_mtu(owner, path_mtu)
    }

    pub(crate) fn process_fsp_mmp_receiver_report(
        &mut self,
        owner: OwnerId,
        rr: &crate::mmp::report::ReceiverReport,
        last_outbound_next_hop: Option<NodeAddr>,
        now_ms: u64,
        now: std::time::Instant,
        min_loss_sample: u64,
    ) -> Result<DataplaneFspReceiverReportResult, DataplaneFspMmpSkip> {
        self.mover.process_fsp_mmp_receiver_report(
            owner,
            rr,
            last_outbound_next_hop,
            now_ms,
            now,
            min_loss_sample,
        )
    }

    pub(crate) fn apply_fsp_path_mtu_signal(
        &mut self,
        owner: OwnerId,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<DataplaneFspPathMtuApplyResult, DataplaneFspMmpSkip> {
        self.mover.apply_fsp_path_mtu_signal(owner, path_mtu, now)
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
        session: DataplaneAuthenticatedFspSession,
    ) -> Option<bool> {
        self.mover.record_authenticated_fsp_session(session)
    }

    fn record_fsp_session_ingress_activity(
        &mut self,
        ingress: &DataplaneFspSessionIngress,
    ) -> bool {
        let body_len = ingress
            .receive_sync
            .plaintext_len
            .saturating_sub(FSP_INNER_HEADER_SIZE);
        self.record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
            ingress.source_addr,
            ingress.previous_hop_addr,
            ingress.msg_type,
            body_len,
            ingress.receive_sync,
            ingress.activity_tick,
            std::time::Instant::now(),
        ))
        .unwrap_or(false)
    }

    pub(crate) fn record_fsp_decrypt_failure(&mut self, owner: OwnerId) -> Option<u32> {
        self.mover.record_fsp_decrypt_failure(owner)
    }

    async fn finish_aead_live_node_output_turn(
        &mut self,
        request: DataplaneLiveOutputRequest<'_>,
    ) -> DataplaneLiveNodeTurn {
        let DataplaneLiveOutputRequest {
            summary,
            routes,
            endpoint_tx,
            transports,
            deferred_raw_ingress,
            crypto_limit,
            collect_transport_sent_receipts,
            crypto_worker,
            transport_send_batch_packets,
        } = request;
        let compact_endpoint_data = endpoint_tx.direct_sink().is_some();
        let summary = self.collect_live_session_outputs(
            summary,
            routes,
            crypto_limit,
            crypto_worker,
            compact_endpoint_data,
            deferred_raw_ingress,
        );
        let mut transport_output = std::mem::take(&mut self.transport_output);
        transport_output.clear();
        let mut report = {
            let mut sink = DataplaneLiveOutputSink::new(&mut transport_output);
            let turn = self.send_collected_outputs(summary, &mut sink);
            DataplaneLiveNodeTurn::from_runtime_turn(&turn)
        };
        self.deliver_direct_endpoint_packet_batches(endpoint_tx.direct_sink());
        report.fmp_ingress_receipts = std::mem::take(&mut self.fmp_ingress_receipts);
        report.fmp_link_ingress = std::mem::take(&mut self.fmp_link_ingress);
        report.fsp_coord_warmups = std::mem::take(&mut self.fsp_coord_warmups);
        report.fsp_local_session_ingress = std::mem::take(&mut self.fsp_local_session_ingress);
        report.transport_planned = transport_output.planned_packets();
        let dropped_before = report.output_drops.len();
        let mut transport_sent_receipts = if collect_transport_sent_receipts {
            Some(&mut report.transport_sent_receipts)
        } else {
            None
        };
        report.transport_sent = {
            let _transport_send_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::DataplaneTransportSend,
            );
            let groups = transport_output.take_groups_preserving_capacity();
            send_dataplane_transport_groups(
                transports,
                groups,
                &mut report.output_drops,
                transport_send_batch_packets,
                transport_sent_receipts.take(),
            )
            .await
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
        report.fsp_authenticated_ingress = std::mem::take(&mut self.fsp_authenticated_ingress);
        self.transport_output = transport_output;
        report
    }

    fn start_aead_completion_turn(
        &mut self,
        completion_limit: usize,
        compact_endpoint_data: bool,
    ) -> DataplaneRuntimeSummary {
        self.reset_turn_buffers();
        self.drain_aead_completion_turn_into_summary(
            DataplaneRuntimeSummary::default(),
            completion_limit,
            compact_endpoint_data,
        )
    }

    fn drain_aead_completion_turn_into_summary(
        &mut self,
        mut summary: DataplaneRuntimeSummary,
        completion_limit: usize,
        compact_endpoint_data: bool,
    ) -> DataplaneRuntimeSummary {
        let _completion_timer = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::DataplaneCompletionDrain,
        );
        let completion_limit = self.completion_drain_limit(completion_limit);
        let retired = self.retire_ready_aead_outputs(completion_limit, compact_endpoint_data);
        summary.completions = summary.completions.saturating_add(retired);
        self.admit_retired_outbound_packets(summary)
    }

    fn completion_drain_limit(&self, limit: usize) -> usize {
        if limit < DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS || self.mover.has_priority_pending() {
            return limit;
        }
        limit.saturating_mul(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS)
    }

    async fn pump_aead_live_node_route_table_turn_after_completion_with_firsts<RI>(
        &mut self,
        request: DataplaneLivePumpRequest<'_, RI>,
    ) -> DataplaneLiveNodeTurn
    where
        RI: DataplaneRawIngressSource,
    {
        let DataplaneLivePumpRequest {
            summary,
            crypto_worker,
            fast_ingress,
            raw_ingress,
            routes,
            raw_ingress_limit,
            endpoint_data_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            outbound_firsts,
            deferred_endpoint_data_batches,
            deferred_tun_packets,
            deferred_raw_ingress,
            endpoint_tx,
            transports,
            crypto_limit,
            transport_send_batch_packets,
        } = request;
        let collect_transport_sent_receipts = outbound_firsts.collect_transport_sent_receipts;
        let mut completion_report = None;
        let mut admission_summary = summary;
        let mut completion_deferred_raw_ingress = std::collections::VecDeque::new();
        // Ready completions are already owner-ordered work. Let their local
        // continuations consume this turn's bounded crypto budget before
        // admitting fresh raw/outbound packets.
        let mut remaining_crypto_limit = crypto_limit;
        if admission_summary.has_activity() {
            let report = self
                .finish_aead_live_node_output_turn(DataplaneLiveOutputRequest {
                    summary: admission_summary,
                    routes,
                    endpoint_tx,
                    transports,
                    deferred_raw_ingress: &mut completion_deferred_raw_ingress,
                    crypto_limit: remaining_crypto_limit,
                    collect_transport_sent_receipts,
                    crypto_worker: &mut *crypto_worker,
                    transport_send_batch_packets,
                })
                .await;
            remaining_crypto_limit =
                remaining_crypto_limit.saturating_sub(report.summary().dispatched());
            self.reset_turn_buffers();
            completion_report = Some(report);
            admission_summary = DataplaneRuntimeSummary::default();
        }
        let admission = self.admit_live_node_route_table_turn_with_firsts(
            DataplaneLiveAdmissionRequest {
                summary: admission_summary,
                fast_ingress,
                raw_ingress,
                routes,
                raw_ingress_limit,
                endpoint_data_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                outbound_firsts,
                deferred_raw_ingress,
            },
        );
        deferred_raw_ingress.append(&mut completion_deferred_raw_ingress);
        if let Some(mut completion_report) = completion_report {
            if !admission.has_activity() {
                return completion_report;
            }
            let report = self
                .finish_live_node_turn_after_admission(
                    DataplaneLiveFinishRequest {
                        admission,
                        routes,
                        endpoint_tx,
                        transports,
                        crypto_limit: remaining_crypto_limit,
                        collect_transport_sent_receipts,
                        crypto_worker,
                        transport_send_batch_packets,
                        deferred_raw_ingress,
                        deferred_endpoint_data_batches,
                        deferred_tun_packets,
                    },
                )
                .await;
            completion_report.absorb(report);
            completion_report
        } else {
            self.finish_live_node_turn_after_admission(
                DataplaneLiveFinishRequest {
                    admission,
                    routes,
                    endpoint_tx,
                    transports,
                    crypto_limit: remaining_crypto_limit,
                    collect_transport_sent_receipts,
                    crypto_worker,
                    transport_send_batch_packets,
                    deferred_raw_ingress,
                    deferred_endpoint_data_batches,
                    deferred_tun_packets,
                },
            )
            .await
        }
    }
}
