impl DataplaneTurnDriver {
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
        self.admit_outbound_packets(
            &mut outbound_firsts.initial_outbound_batch,
            &mut summary,
        );

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

    async fn finish_live_node_turn_after_admission(
        &mut self,
        request: DataplaneLiveFinishRequest<'_>,
    ) -> DataplaneLiveNodeTurn {
        let DataplaneLiveFinishRequest {
            admission,
            routes,
            endpoint_tx,
            transports,
            crypto_limit,
            collect_transport_sent_receipts,
            crypto_worker,
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
            .finish_aead_live_node_output_turn(DataplaneLiveOutputRequest {
                summary,
                routes,
                endpoint_tx,
                transports,
                deferred_raw_ingress,
                crypto_limit,
                collect_transport_sent_receipts,
                crypto_worker,
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

        let (counter, ciphertext_offset, wire_flags) = header.open_metadata();
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
            counter,
            ciphertext_offset,
            route.class,
            route.output,
            payload,
        )
        .with_source_path(source_path);
        socket_packet = socket_packet.with_path_mtu(path_mtu);
        socket_packet = socket_packet.with_receive_epoch(route.receive_epoch);
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

    fn retire_ready_aead_outputs(
        &mut self,
        limit: usize,
        compact_endpoint_data: bool,
    ) -> usize {
        let retired_completions = self
            .mover
            .retire_ready_slots_into(
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
        retired_completions
    }

    fn collect_live_session_outputs<R>(
        &mut self,
        mut summary: DataplaneRuntimeSummary,
        router: &mut R,
        crypto_limit: usize,
        crypto_worker: &mut DataplaneAeadWorkerPool,
        compact_endpoint_data: bool,
        deferred_raw_ingress: &mut std::collections::VecDeque<(DataplaneRawIngress, u8)>,
    ) -> DataplaneRuntimeSummary
    where
        R: DataplaneIngressRouter,
    {
        let mut remaining = crypto_limit;
        self.process_live_internal_outputs(router, &mut summary, deferred_raw_ingress);
        loop {
            let dispatched_before = summary.dispatched;
            summary = self.collect_aead_outputs(
                summary,
                remaining,
                crypto_worker,
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

    fn collect_aead_outputs(
        &mut self,
        mut summary: DataplaneRuntimeSummary,
        limit: usize,
        crypto_worker: &mut DataplaneAeadWorkerPool,
        compact_endpoint_data: bool,
    ) -> DataplaneRuntimeSummary {
        let mut remaining = limit;
        while remaining > 0 {
            let dispatched = {
                let _dispatch_timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::DataplaneAeadDispatch,
                );
                self.mover.run_aead_available_into(
                    remaining,
                    DataplaneAeadRunBuffers::new(
                        &mut self.prepared_work,
                        &mut self.ready_slots,
                        &mut self.outputs,
                        &mut self.retired_outbound_packets,
                        &mut self.fsp_authenticated_ingress,
                        &mut self.drops,
                    ),
                    crypto_worker,
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
            if !bulk.has_direct_packet_runs() {
                continue;
            }
            let count = bulk.len();
            if sink_failed {
                let _ = bulk.take_direct_packet_batch();
                dropped = dropped.saturating_add(count);
                continue;
            }
            let packet_batch = bulk.take_direct_packet_batch();
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
