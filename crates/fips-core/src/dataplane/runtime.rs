const DATAPLANE_DEFERRED_RAW_INGRESS_MAX_RETRIES: u8 = 8;

#[derive(Debug)]
pub(crate) struct DataplaneTurnDriver {
    mover: Dataplane,
    prepared_work: Vec<PreparedCryptoWork>,
    completion_work: Vec<CryptoCompletion>,
    completion_batches: Vec<CryptoCompletionBatch>,
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
    deferred_raw_ingress: &'a mut std::collections::VecDeque<(DataplaneRawIngress, u8)>,
}

struct DataplaneLiveOutputRequest<'a, E> {
    summary: DataplaneRuntimeSummary,
    routes: &'a mut DataplaneLiveRouteTable,
    endpoint_tx: &'a EndpointEventSender,
    transports: &'a HashMap<TransportId, TransportHandle>,
    deferred_raw_ingress: &'a mut std::collections::VecDeque<(DataplaneRawIngress, u8)>,
    crypto_limit: usize,
    collect_transport_sent_receipts: bool,
    executor: &'a mut E,
    transport_send_batch_packets: usize,
}

struct DataplaneLiveFinishRequest<'a, E> {
    admission: DataplaneLiveAdmissionResult,
    routes: &'a mut DataplaneLiveRouteTable,
    endpoint_tx: &'a EndpointEventSender,
    transports: &'a HashMap<TransportId, TransportHandle>,
    crypto_limit: usize,
    collect_transport_sent_receipts: bool,
    executor: &'a mut E,
    transport_send_batch_packets: usize,
    deferred_raw_ingress: &'a mut std::collections::VecDeque<(DataplaneRawIngress, u8)>,
    deferred_endpoint_data_batches: &'a mut Vec<NodeEndpointDataBatch>,
    deferred_tun_packets: &'a mut Vec<Vec<u8>>,
}

struct DataplaneLivePumpRequest<'a, E, RI> {
    summary: DataplaneRuntimeSummary,
    executor: &'a mut E,
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
    deferred_raw_ingress: &'a mut std::collections::VecDeque<(DataplaneRawIngress, u8)>,
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
            completion_work: Vec::new(),
            completion_batches: Vec::new(),
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

    async fn finish_aead_live_node_output_turn_with_executor<E>(
        &mut self,
        request: DataplaneLiveOutputRequest<'_, E>,
    ) -> DataplaneLiveNodeTurn
    where
        E: DataplaneCryptoExecutor,
    {
        let DataplaneLiveOutputRequest {
            summary,
            routes,
            endpoint_tx,
            transports,
            deferred_raw_ingress,
            crypto_limit,
            collect_transport_sent_receipts,
            executor,
            transport_send_batch_packets,
        } = request;
        let compact_endpoint_data = endpoint_tx.direct_sink().is_some();
        let summary = self.collect_live_session_outputs_with_executor(
            summary,
            routes,
            crypto_limit,
            executor,
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

    fn start_aead_completion_turn<C>(
        &mut self,
        completions: &mut C,
        completion_limit: usize,
        compact_endpoint_data: bool,
    ) -> DataplaneRuntimeSummary
    where
        C: DataplaneCompletionSource,
    {
        self.reset_turn_buffers();
        self.drain_aead_completion_turn_into_summary(
            DataplaneRuntimeSummary::default(),
            completions,
            completion_limit,
            compact_endpoint_data,
        )
    }

    fn drain_aead_completion_turn_into_summary<C>(
        &mut self,
        mut summary: DataplaneRuntimeSummary,
        completions: &mut C,
        completion_limit: usize,
        compact_endpoint_data: bool,
    ) -> DataplaneRuntimeSummary
    where
        C: DataplaneCompletionSource,
    {
        let _completion_timer = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::DataplaneCompletionDrain,
        );
        let completion_limit = self.completion_drain_limit(completion_limit);
        let queued = completions.drain_completion_batches_into_sink(
            completion_limit,
            &mut self.mover,
        );
        summary.completions = summary.completions.saturating_add(queued);
        self.retire_queued_completed_aead_outputs(completion_limit, compact_endpoint_data);
        self.admit_retired_outbound_packets(summary)
    }

    fn completion_drain_limit(&self, limit: usize) -> usize {
        if limit < DATAPLANE_AEAD_WORKER_JOB_PACKETS || self.mover.has_priority_pending() {
            return limit;
        }
        limit.saturating_mul(DATAPLANE_AEAD_WORKER_JOB_PACKETS)
    }

    async fn pump_aead_live_node_route_table_executor_turn_after_completion_with_firsts<E, RI>(
        &mut self,
        request: DataplaneLivePumpRequest<'_, E, RI>,
    ) -> DataplaneLiveNodeTurn
    where
        E: DataplaneCryptoExecutor,
        RI: DataplaneRawIngressSource,
    {
        let DataplaneLivePumpRequest {
            summary,
            executor,
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
                .finish_aead_live_node_output_turn_with_executor(DataplaneLiveOutputRequest {
                    summary: admission_summary,
                    routes,
                    endpoint_tx,
                    transports,
                    deferred_raw_ingress: &mut completion_deferred_raw_ingress,
                    crypto_limit: remaining_crypto_limit,
                    collect_transport_sent_receipts,
                    executor: &mut *executor,
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
                        executor,
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
                    executor,
                    transport_send_batch_packets,
                    deferred_raw_ingress,
                    deferred_endpoint_data_batches,
                    deferred_tun_packets,
                },
            )
            .await
        }
    }

    fn admit_live_node_route_table_turn_with_firsts<RI>(
        &mut self,
        request: DataplaneLiveAdmissionRequest<'_, RI>,
    ) -> DataplaneLiveAdmissionResult
    where
        RI: DataplaneRawIngressSource,
    {
        let DataplaneLiveAdmissionRequest {
            mut summary,
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
        } = request;
        let admit_timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneLiveAdmit);
        let trace_enabled = crate::perf_profile::enabled();
        let mut outbound_firsts = outbound_firsts;
        if let Some(packet) = outbound_firsts.initial_outbound.take() {
            self.admit_outbound_packet(packet, &mut summary);
        }

        let routed_outbound_limit = endpoint_limit.saturating_add(tun_limit);
        let reserved_outbound_limit =
            reserved_live_outbound_progress_limit(endpoint_limit, tun_limit, routed_outbound_limit);
        let mut outbound_buffers = DataplaneRouteTableOutboundBuffers::default();
        let mut endpoint_drained = 0usize;
        let mut tun_drained = 0usize;
        let mut outbound_drained = 0usize;
        let mut outbound_admitted = DataplaneOutboundAdmissionCounts::default();

        if reserved_outbound_limit > 0 {
            let mut outbound_source = DataplaneRouteTableOutboundSource::new(
                endpoint_data_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                routes,
                &mut outbound_buffers,
            )
            .with_firsts(outbound_firsts);
            let (drained_total, endpoint, tun) = {
                let mut admission = DataplaneOutboundAdmission {
                    driver: self,
                    summary: &mut summary,
                    trace_enabled,
                    counts: &mut outbound_admitted,
                };
                outbound_source.drain_outbound_batched(reserved_outbound_limit, &mut admission)
            };
            outbound_drained = drained_total;
            endpoint_drained = endpoint_drained.saturating_add(endpoint);
            tun_drained = tun_drained.saturating_add(tun);
            outbound_firsts = outbound_source.take_firsts();
        }

        let mut raw_socket_packets = std::mem::take(&mut self.raw_socket_packets);
        raw_socket_packets.clear();
        let raw_admitted_before = if trace_enabled {
            summary.inbound_admitted
        } else {
            0
        };
        if let Some(fast_ingress) = fast_ingress {
            self.admit_fast_ingress_runs(fast_ingress, &mut summary);
        }
        {
            let raw_ingress_drops = &mut self.raw_ingress_drops;
            let deferred_available = deferred_raw_ingress.len();
            let fresh_drained = raw_ingress.drain_raw_ingress(raw_ingress_limit, |packet| {
                if let Some(socket_packet) =
                    Self::raw_ingress_socket_packet(
                        packet,
                        routes,
                        &mut summary,
                        raw_ingress_drops,
                        deferred_raw_ingress,
                        0,
                    )
                {
                    raw_socket_packets.push(socket_packet);
                }
            });
            let deferred_limit = raw_ingress_limit
                .saturating_sub(fresh_drained)
                .min(deferred_available);
            for _ in 0..deferred_limit {
                let Some((packet, retry_count)) = deferred_raw_ingress.pop_front() else {
                    break;
                };
                if let Some(socket_packet) = Self::raw_ingress_socket_packet(
                    packet,
                    routes,
                    &mut summary,
                    raw_ingress_drops,
                    deferred_raw_ingress,
                    retry_count,
                ) {
                    raw_socket_packets.push(socket_packet);
                }
            }
        }
        self.admit_socket_packets(&mut raw_socket_packets, &mut summary);
        self.raw_socket_packets = raw_socket_packets;
        if trace_enabled {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::DataplaneLiveRawAdmitted,
                summary
                    .inbound_admitted
                    .saturating_sub(raw_admitted_before) as u64,
            );
        }

        let remaining_outbound_limit =
            routed_outbound_limit.saturating_sub(outbound_drained.min(routed_outbound_limit));
        if remaining_outbound_limit > 0 {
            let mut outbound_source = DataplaneRouteTableOutboundSource::new(
                endpoint_data_rx,
                endpoint_limit,
                tun_outbound_rx,
                tun_limit,
                routes,
                &mut outbound_buffers,
            )
            .with_firsts(outbound_firsts);
            let (_, endpoint, tun) = {
                let mut admission = DataplaneOutboundAdmission {
                    driver: self,
                    summary: &mut summary,
                    trace_enabled,
                    counts: &mut outbound_admitted,
                };
                outbound_source.drain_outbound_batched(remaining_outbound_limit, &mut admission)
            };
            endpoint_drained = endpoint_drained.saturating_add(endpoint);
            tun_drained = tun_drained.saturating_add(tun);
        }
        if trace_enabled {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::DataplaneLiveEndpointAdmitted,
                outbound_admitted.endpoint as u64,
            );
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::DataplaneLiveTunAdmitted,
                outbound_admitted.tun as u64,
            );
        }
        drop(admit_timer);

        DataplaneLiveAdmissionResult {
            summary,
            outbound_buffers,
            endpoint_drained,
            tun_drained,
        }
    }

    async fn finish_live_node_turn_after_admission<E>(
        &mut self,
        request: DataplaneLiveFinishRequest<'_, E>,
    ) -> DataplaneLiveNodeTurn
    where
        E: DataplaneCryptoExecutor,
    {
        let DataplaneLiveFinishRequest {
            admission,
            routes,
            endpoint_tx,
            transports,
            crypto_limit,
            collect_transport_sent_receipts,
            executor,
            transport_send_batch_packets,
            deferred_raw_ingress,
            deferred_endpoint_data_batches,
            deferred_tun_packets,
        } = request;
        let DataplaneLiveAdmissionResult {
            summary,
            mut outbound_buffers,
            endpoint_drained,
            tun_drained,
        } = admission;
        let mut report = self
            .finish_aead_live_node_output_turn_with_executor(DataplaneLiveOutputRequest {
                summary,
                routes,
                endpoint_tx,
                transports,
                deferred_raw_ingress,
                crypto_limit,
                collect_transport_sent_receipts,
                executor,
                transport_send_batch_packets,
            })
            .await;
        let endpoint_deferred_count = outbound_buffers.deferred_endpoint_data_batches.len();
        deferred_endpoint_data_batches.append(&mut outbound_buffers.deferred_endpoint_data_batches);
        let tun_deferred_count = outbound_buffers.tun_deferred_packets.len();
        deferred_tun_packets.append(&mut outbound_buffers.tun_deferred_packets);
        report.endpoint_data_drops = outbound_buffers.endpoint_drops;
        report.endpoint_source_drained = endpoint_drained;
        report.deferred_endpoint_data_batches_count = endpoint_deferred_count;
        report.tun_outbound_drops = outbound_buffers.tun_drops;
        report.tun_deferred_packets = tun_deferred_count;
        report.tun_source_drained = tun_drained;
        report
    }

    fn reset_turn_buffers(&mut self) {
        self.outputs.clear();
        self.output_rewrite_buffer.clear();
        self.raw_socket_packets.clear();
        self.retired_outbound_packets.clear();
        self.transport_output.clear();
        self.drops.clear();
        self.raw_ingress_drops.clear();
        self.output_drops.clear();
        self.fmp_ingress_receipts.clear();
        self.fmp_link_ingress.clear();
        self.fsp_coord_warmups.clear();
        self.fsp_local_session_ingress.clear();
        self.fsp_authenticated_ingress.clear();
    }

    fn raw_ingress_socket_packet<R>(
        packet: DataplaneRawIngress,
        router: &mut R,
        summary: &mut DataplaneRuntimeSummary,
        raw_ingress_drops: &mut Vec<DataplaneRawIngressDrop>,
        deferred_raw_ingress: &mut std::collections::VecDeque<(DataplaneRawIngress, u8)>,
        retry_count: u8,
    ) -> Option<SocketPacket>
    where
        R: DataplaneIngressRouter,
    {
        let header = match packet.protocol {
            PacketProtocol::Fmp => match FmpWireHeader::parse(packet.payload.as_slice()) {
                Ok(header) => DataplaneIngressHeader::Fmp(header),
                Err(error) => {
                    summary.raw_ingress_dropped += 1;
                    raw_ingress_drops.push(DataplaneRawIngressDrop::from_packet(
                        packet,
                        DataplaneRawIngressDropReason::Wire(error),
                    ));
                    return None;
                }
            },
            PacketProtocol::Fsp => match FspWireHeader::parse(packet.payload.as_slice()) {
                Ok(header) => DataplaneIngressHeader::Fsp(header),
                Err(error) => {
                    summary.raw_ingress_dropped += 1;
                    raw_ingress_drops.push(DataplaneRawIngressDrop::from_packet(
                        packet,
                        DataplaneRawIngressDropReason::Wire(error),
                    ));
                    return None;
                }
            },
        };

        let Some(route) = router.route(&packet, header) else {
            if packet.protocol == PacketProtocol::Fsp
                && packet.fsp_source.is_some()
                && retry_count < DATAPLANE_DEFERRED_RAW_INGRESS_MAX_RETRIES
            {
                deferred_raw_ingress.push_back((packet, retry_count.saturating_add(1)));
                return None;
            }
            summary.raw_ingress_dropped += 1;
            raw_ingress_drops.push(DataplaneRawIngressDrop::from_packet(
                packet,
                DataplaneRawIngressDropReason::Unrouted,
            ));
            return None;
        };

        let wire_flags = header.flags();
        let DataplaneRawIngress {
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
        Some(socket_packet)
    }

    fn admit_socket_packet(
        &mut self,
        packet: SocketPacket,
        summary: &mut DataplaneRuntimeSummary,
    ) {
        match self.mover.submit_socket_packet(packet) {
            Ok(_) => summary.inbound_admitted += 1,
            Err(_) => summary.inbound_dropped += 1,
        }
    }

    fn admit_socket_packets(
        &mut self,
        packets: &mut Vec<SocketPacket>,
        summary: &mut DataplaneRuntimeSummary,
    ) {
        match packets.len() {
            0 => {}
            1 => {
                let packet = packets.pop().expect("checked one packet");
                self.admit_socket_packet(packet, summary);
            }
            _ => {
                let capacity = packets.capacity();
                let batch = std::mem::replace(packets, Vec::with_capacity(capacity));
                let (admitted, dropped) = self.mover.submit_socket_packet_batch(batch);
                summary.inbound_admitted = summary.inbound_admitted.saturating_add(admitted);
                summary.inbound_dropped = summary.inbound_dropped.saturating_add(dropped);
            }
        }
    }

    fn admit_fast_ingress_runs(
        &mut self,
        fast_ingress: DataplaneFastIngressBatch,
        summary: &mut DataplaneRuntimeSummary,
    ) {
        for run in fast_ingress.into_runs() {
            let run_len = run.len();
            crate::perf_profile::record_dataplane_fast_ingress_owner_run(run_len);
            let (owner, lane, packets) = run.into_parts();
            let (admitted, dropped) =
                self.mover.submit_socket_packet_run(Some(owner), Some(lane), packets);
            summary.inbound_admitted = summary.inbound_admitted.saturating_add(admitted);
            summary.inbound_dropped = summary.inbound_dropped.saturating_add(dropped);
        }
    }

    fn admit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
        summary: &mut DataplaneRuntimeSummary,
    ) {
        match self.mover.submit_outbound_packet(packet) {
            Ok(_) => summary.outbound_admitted += 1,
            Err(_) => summary.outbound_dropped += 1,
        }
    }

    fn admit_outbound_packet_batch(
        &mut self,
        packets: Vec<OutboundPacket>,
        summary: &mut DataplaneRuntimeSummary,
    ) {
        let packet_count = packets.len();
        crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneOutboundBatchAdmit);
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneOutboundBatchPackets,
            packet_count as u64,
        );
        let (admitted, dropped) = self.mover.submit_outbound_packet_batch(packets);
        summary.outbound_admitted = summary.outbound_admitted.saturating_add(admitted);
        summary.outbound_dropped = summary.outbound_dropped.saturating_add(dropped);
    }

    fn admit_outbound_packets(
        &mut self,
        packets: &mut Vec<OutboundPacket>,
        summary: &mut DataplaneRuntimeSummary,
    ) {
        match packets.len() {
            0 => {}
            1 => {
                let packet = packets.pop().expect("checked one packet");
                self.admit_outbound_packet(packet, summary);
            }
            _ => {
                let capacity = packets.capacity();
                let batch = std::mem::replace(packets, Vec::with_capacity(capacity));
                self.admit_outbound_packet_batch(batch, summary);
            }
        }
    }

    fn send_collected_outputs<S>(
        &mut self,
        mut summary: DataplaneRuntimeSummary,
        sink: &mut S,
    ) -> DataplaneRuntimeTurn<'_>
    where
        S: DataplaneOutputSink,
    {
        let dropped_before = self.output_drops.len();
        let sent = if self.outputs.is_empty() {
            0
        } else {
            crate::perf_profile::record_dataplane_live_output_batch(self.outputs.len());
            let _output_sink_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::DataplaneOutputSink,
            );
            sink.send_batch(self.outputs.drain(..), &mut self.output_drops)
        };
        summary.outputs_sent += sent;
        summary.outputs_dropped += self.output_drops.len().saturating_sub(dropped_before);

        DataplaneRuntimeTurn {
            summary,
            raw_ingress_drops: &self.raw_ingress_drops,
            output_drops: &self.output_drops,
            outputs: &self.outputs,
            drops: &self.drops,
        }
    }

    fn process_live_internal_outputs<R>(
        &mut self,
        router: &mut R,
        summary: &mut DataplaneRuntimeSummary,
        deferred_raw_ingress: &mut std::collections::VecDeque<(DataplaneRawIngress, u8)>,
    ) -> usize
    where
        R: DataplaneIngressRouter,
    {
        let mut outputs = self.take_outputs_for_rewrite();
        let mut raw_socket_packets = std::mem::take(&mut self.raw_socket_packets);
        raw_socket_packets.clear();
        let dropped_before = self.output_drops.len();
        let admitted_before = summary.inbound_admitted;
        for output in outputs.drain(..) {
            match output.target {
                OutputTarget::SessionIngress { local_addr } => {
                    let receipt = DataplaneFmpIngressReceipt::from_output(&output);
                    match dataplane_session_ingress_from_output(output, local_addr) {
                        DataplaneSessionIngressHandoff::Raw { raw, coord_warmup } => {
                            if let Some(receipt) = receipt {
                                self.fmp_ingress_receipts.push(receipt);
                            }
                            if !coord_warmup.is_empty() {
                                self.fsp_coord_warmups.push(coord_warmup);
                            }
                            if let Some(socket_packet) = Self::raw_ingress_socket_packet(
                                raw,
                                router,
                                summary,
                                &mut self.raw_ingress_drops,
                                deferred_raw_ingress,
                                1,
                            ) {
                                raw_socket_packets.push(socket_packet);
                            }
                        }
                        DataplaneSessionIngressHandoff::Local(ingress) => {
                            if let Some(receipt) = receipt {
                                self.fmp_ingress_receipts.push(receipt);
                            }
                            self.fsp_local_session_ingress.push(ingress);
                        }
                        DataplaneSessionIngressHandoff::Rejected {
                            output,
                            error: DataplaneSessionHandoffError::NoRoute,
                        } => {
                            if let Some(receipt) = receipt {
                                self.fmp_link_ingress
                                    .push(DataplaneFmpLinkIngress::from_output(output, receipt));
                            } else {
                                self.output_drops.push(DataplaneOutputDrop::from_output(
                                    &output,
                                    DataplaneOutputError::NoRoute,
                                ));
                            }
                        }
                        DataplaneSessionIngressHandoff::Rejected { output, error } => {
                            self.output_drops.push(DataplaneOutputDrop::from_output(
                                &output,
                                dataplane_output_error_from_session_handoff(error),
                            ))
                        }
                    }
                }
                OutputTarget::SessionPayload { .. } => {
                    let mut output = output;
                    if let Some(ingress) =
                        DataplaneFspSessionIngress::take_from_output(&mut output)
                    {
                        self.record_fsp_session_ingress_activity(&ingress);
                        self.fsp_authenticated_ingress.push_session(ingress);
                    } else {
                        self.output_drops.push(DataplaneOutputDrop::from_output(
                            &output,
                            DataplaneOutputError::InvalidPacket,
                        ));
                    }
                }
                _ => self.outputs.push(output),
            }
        }
        self.admit_socket_packets(&mut raw_socket_packets, summary);
        self.raw_socket_packets = raw_socket_packets;
        self.output_rewrite_buffer = outputs;
        summary.outputs = self.outputs.len();
        summary.outputs_dropped = summary
            .outputs_dropped
            .saturating_add(self.output_drops.len().saturating_sub(dropped_before));
        summary.inbound_admitted.saturating_sub(admitted_before)
    }

    fn retire_queued_completed_aead_outputs(
        &mut self,
        limit: usize,
        compact_endpoint_data: bool,
    ) {
        let retired_completions = self
            .mover
            .retire_queued_completions_into(
                limit,
                &mut DataplaneRetiredOutputSink::new(
                    &mut self.outputs,
                    &mut self.retired_outbound_packets,
                    &mut self.fsp_authenticated_ingress,
                ),
                compact_endpoint_data,
            );
        crate::perf_profile::record_dataplane_live_completions_retired(retired_completions);
        let mut mover_drops = self.mover.drain_drops();
        self.drops.append(&mut mover_drops);
    }

    fn collect_live_session_outputs_with_executor<R, E>(
        &mut self,
        mut summary: DataplaneRuntimeSummary,
        router: &mut R,
        crypto_limit: usize,
        executor: &mut E,
        compact_endpoint_data: bool,
        deferred_raw_ingress: &mut std::collections::VecDeque<(DataplaneRawIngress, u8)>,
    ) -> DataplaneRuntimeSummary
    where
        R: DataplaneIngressRouter,
        E: DataplaneCryptoExecutor,
    {
        let mut remaining = crypto_limit;
        self.process_live_internal_outputs(router, &mut summary, deferred_raw_ingress);
        loop {
            let dispatched_before = summary.dispatched;
            summary = self.collect_aead_outputs_with_executor(
                summary,
                remaining,
                executor,
                compact_endpoint_data,
            );
            let dispatched = summary.dispatched.saturating_sub(dispatched_before);
            remaining = remaining.saturating_sub(dispatched);
            if remaining == 0 {
                break;
            }

            if self.process_live_internal_outputs(router, &mut summary, deferred_raw_ingress) == 0 {
                break;
            }
        }
        self.process_live_internal_outputs(router, &mut summary, deferred_raw_ingress);
        summary
    }

    fn take_outputs_for_rewrite(&mut self) -> Vec<PacketOutput> {
        let mut outputs = std::mem::take(&mut self.output_rewrite_buffer);
        std::mem::swap(&mut self.outputs, &mut outputs);
        outputs
    }

    fn collect_aead_outputs_with_executor<E>(
        &mut self,
        mut summary: DataplaneRuntimeSummary,
        limit: usize,
        executor: &mut E,
        compact_endpoint_data: bool,
    ) -> DataplaneRuntimeSummary
    where
        E: DataplaneCryptoExecutor,
    {
        let mut remaining = limit;
        while remaining > 0 {
            let dispatched = {
                let _dispatch_timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::DataplaneAeadDispatch,
                );
                self.mover.run_aead_available_into_with_executor(
                    remaining,
                    DataplaneAeadRunBuffers::new(
                        &mut self.prepared_work,
                        &mut self.completion_work,
                        &mut self.completion_batches,
                        &mut self.outputs,
                        &mut self.retired_outbound_packets,
                        &mut self.fsp_authenticated_ingress,
                        &mut self.drops,
                    ),
                    executor,
                    compact_endpoint_data,
                )
            };
            summary.dispatched = summary.dispatched.saturating_add(dispatched);
            remaining = remaining.saturating_sub(dispatched);

            let outbound_admitted_before = summary.outbound_admitted;
            summary = self.admit_retired_outbound_packets(summary);

            if dispatched == 0 && summary.outbound_admitted == outbound_admitted_before {
                break;
            }
        }

        summary.outputs = self.outputs.len();
        summary.drops = self.drops.len();
        summary
    }

    fn admit_retired_outbound_packets(
        &mut self,
        mut summary: DataplaneRuntimeSummary,
    ) -> DataplaneRuntimeSummary {
        let mut outbound_packets = std::mem::take(&mut self.retired_outbound_packets);
        for packet in &mut outbound_packets {
            self.refresh_wrapped_fsp_outbound_context(packet);
        }
        self.admit_outbound_packets(&mut outbound_packets, &mut summary);
        self.retired_outbound_packets = outbound_packets;
        summary.outputs = self.outputs.len();
        summary.drops = self.drops.len();
        summary
    }

    fn refresh_wrapped_fsp_outbound_context(&self, packet: &mut OutboundPacket) {
        if !packet.has_fsp_send_receipt() || packet.owner().protocol() != PacketProtocol::Fmp {
            return;
        }
        let Some(context) = self.owner_fmp_send_context(packet.owner()) else {
            return;
        };
        packet.refresh_fmp_send_context(
            context.generation(),
            context.receiver_idx(),
            context.flags(),
        );
    }

    fn deliver_direct_endpoint_packet_batches(&mut self, direct_sink: Option<&EndpointDirectSink>) {
        let Some(direct_sink) = direct_sink else {
            return;
        };

        let mut dropped = 0usize;
        let mut sink_failed = false;
        for bulk in self.fsp_authenticated_ingress.endpoint_data_batches_mut() {
            let count = bulk.packet_count();
            let packet_batch = bulk.take_direct_packet_batch();
            if count == 0 {
                continue;
            }
            if sink_failed {
                dropped = dropped.saturating_add(count);
                continue;
            }
            if direct_sink.deliver_direct_packet_batch(packet_batch).is_err() {
                dropped = dropped.saturating_add(count);
                sink_failed = true;
            }
        }

        if dropped > 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::EndpointEventBulkDropped,
                dropped as u64,
            );
        }
    }
}
