#[derive(Debug)]
pub(crate) struct Dataplane {
    config: AdmissionConfig,
    shards: Vec<DataplaneOwnerShard>,
    retire_workers: Vec<DataplaneOwnerShardRetireWorker>,
    admission_lens: LaneLens,
    outbound_admission_lens: LaneLens,
    drops: Vec<PacketDrop>,
    next_ingress_seq: u64,
    next_outbound_seq: u64,
    ingress_ready_shards: ReadyShardQueues,
    outbound_ready_shards: ReadyShardQueues,
    completion_ready_shards: ReadyShardQueue,
}

pub(crate) struct DataplaneAeadRunBuffers<'a> {
    prepared_work: &'a mut Vec<PreparedCryptoWork>,
    completion_work: &'a mut Vec<CryptoCompletion>,
    completion_batches: &'a mut Vec<CryptoCompletionBatch>,
    outputs: &'a mut Vec<PacketOutput>,
    outbound_packets: &'a mut Vec<OutboundPacket>,
    fsp_authenticated_ingress: &'a mut DataplaneFspAuthenticatedIngress,
    drops: &'a mut Vec<PacketDrop>,
}

impl<'a> DataplaneAeadRunBuffers<'a> {
    pub(crate) fn new(
        prepared_work: &'a mut Vec<PreparedCryptoWork>,
        completion_work: &'a mut Vec<CryptoCompletion>,
        completion_batches: &'a mut Vec<CryptoCompletionBatch>,
        outputs: &'a mut Vec<PacketOutput>,
        outbound_packets: &'a mut Vec<OutboundPacket>,
        fsp_authenticated_ingress: &'a mut DataplaneFspAuthenticatedIngress,
        drops: &'a mut Vec<PacketDrop>,
    ) -> Self {
        Self {
            prepared_work,
            completion_work,
            completion_batches,
            outputs,
            outbound_packets,
            fsp_authenticated_ingress,
            drops,
        }
    }
}

impl Dataplane {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        let shard_count = dataplane_owner_shard_count(config);
        let shards = (0..shard_count)
            .map(DataplaneOwnerShard::new)
            .collect();
        let retire_workers = (0..shard_count)
            .map(|_| DataplaneOwnerShardRetireWorker::new())
            .collect();
        Self {
            config,
            shards,
            retire_workers,
            admission_lens: LaneLens::default(),
            outbound_admission_lens: LaneLens::default(),
            drops: Vec::new(),
            next_ingress_seq: 0,
            next_outbound_seq: 0,
            ingress_ready_shards: ReadyShardQueues::new(shard_count),
            outbound_ready_shards: ReadyShardQueues::new(shard_count),
            completion_ready_shards: ReadyShardQueue::new(shard_count),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.owner_shard_mut(owner).register_owner(owner, config);
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> bool {
        self.owner_shard_mut(owner).unregister_owner(owner)
    }

    pub(crate) fn has_owner(&self, owner: OwnerId) -> bool {
        self.owner_shard(owner).has_owner(owner)
    }

    pub(crate) fn has_runnable_work(&self) -> bool {
        self.ingress_ready_shards.has_ready()
            || self.outbound_ready_shards.has_ready()
            || self.completion_ready_shards.has_ready()
    }

    pub(crate) fn fsp_owner_destinations(&self) -> Vec<NodeAddr> {
        let mut destinations = Vec::new();
        for shard in &self.shards {
            shard.fsp_owner_destinations(&mut destinations);
        }
        destinations
    }

    pub(crate) fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.owner_shard(owner).owner_active_path(owner)
    }

    pub(crate) fn owner_fsp_next_hop(&self, owner: OwnerId) -> Option<NodeAddr> {
        self.owner_shard(owner).owner_fsp_next_hop(owner)
    }

    pub(crate) fn owner_fsp_activity(
        &self,
        owner: OwnerId,
    ) -> Option<DataplaneFspOwnerActivity> {
        self.owner_shard(owner).owner_fsp_activity(owner)
    }

    pub(crate) fn owner_has_fsp_pending_receive_epoch(
        &self,
        owner: OwnerId,
        received_k_bit: bool,
    ) -> bool {
        self.owner_shard(owner)
            .owner_has_fsp_pending_receive_epoch(owner, received_k_bit)
    }

    pub(crate) fn owner_has_fmp_pending_receive_epoch(
        &self,
        owner: OwnerId,
        received_k_bit: bool,
    ) -> bool {
        self.owner_shard(owner)
            .owner_has_fmp_pending_receive_epoch(owner, received_k_bit)
    }

    pub(crate) fn owner_fsp_mmp_snapshot(
        &self,
        owner: OwnerId,
    ) -> Option<DataplaneFspMmpSnapshot> {
        self.owner_shard(owner).owner_fsp_mmp_snapshot(owner)
    }

    pub(crate) fn owner_fsp_send_context(
        &self,
        owner: OwnerId,
    ) -> Option<DataplaneFspSendContext> {
        self.owner_shard(owner).owner_fsp_send_context(owner)
    }

    pub(crate) fn owner_fmp_send_context(
        &self,
        owner: OwnerId,
    ) -> Option<DataplaneFmpSendContext> {
        self.owner_shard(owner).owner_fmp_send_context(owner)
    }

    pub(crate) fn owner_fmp_link_metrics(
        &self,
        owner: OwnerId,
        now: std::time::Instant,
    ) -> Option<DataplaneFmpLinkMetrics> {
        self.owner_shard(owner).owner_fmp_link_metrics(owner, now)
    }

    pub(crate) fn owner_fmp_link_cost(&self, owner: OwnerId) -> Option<f64> {
        self.owner_shard(owner).owner_fmp_link_cost(owner)
    }

    pub(crate) fn owner_fmp_has_srtt(&self, owner: OwnerId) -> bool {
        self.owner_shard(owner).owner_fmp_has_srtt(owner)
    }

    pub(crate) fn collect_fmp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> DataplaneFmpMmpReportBatch {
        let mut batch = DataplaneFmpMmpReportBatch::default();
        for shard in &mut self.shards {
            shard.collect_fmp_mmp_reports(now, &mut batch);
        }
        batch
    }

    pub(crate) fn collect_fsp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> DataplaneFspMmpReportBatch {
        let mut batch = DataplaneFspMmpReportBatch::default();
        for shard in &mut self.shards {
            shard.collect_fsp_mmp_reports(now, &mut batch);
        }
        batch
    }

    pub(crate) fn record_fsp_mmp_send_result(
        &mut self,
        owner: OwnerId,
        success: bool,
    ) -> Option<DataplaneFspMmpReportingResumed> {
        self.owner_shard_mut(owner)
            .record_fsp_mmp_send_result(owner, success)
    }

    pub(crate) fn seed_fsp_path_mtu(
        &mut self,
        owner: OwnerId,
        path_mtu: u16,
    ) -> Result<(), DataplaneFspMmpSkip> {
        self.owner_shard_mut(owner)
            .seed_fsp_path_mtu(owner, path_mtu)
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
        self.owner_shard_mut(owner)
            .process_fsp_mmp_receiver_report(
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
        self.owner_shard_mut(owner)
            .apply_fsp_path_mtu_signal(owner, path_mtu, now)
    }

    pub(crate) fn min_fsp_rx_age_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
    ) -> Option<u64> {
        self.shards
            .iter()
            .filter_map(|shard| shard.min_fsp_rx_age_for_next_hop(next_hop, now_ms))
            .min()
    }

    pub(crate) fn min_fsp_data_rx_age_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
    ) -> Option<u64> {
        self.shards
            .iter()
            .filter_map(|shard| shard.min_fsp_data_rx_age_for_next_hop(next_hop, now_ms))
            .min()
    }

    pub(crate) fn any_fsp_recent_outbound_without_inbound_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
        timeout_ms: u64,
    ) -> bool {
        self.shards.iter().any(|shard| {
            shard.any_fsp_recent_outbound_without_inbound_for_next_hop(
                next_hop, now_ms, timeout_ms,
            )
        })
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owner_shard_mut(owner).owner_mut(owner)
    }

    pub(crate) fn record_authenticated_fsp_session(
        &mut self,
        session: DataplaneAuthenticatedFspSession,
    ) -> Option<bool> {
        self.owner_shard_mut(session.owner)
            .record_authenticated_fsp_session(session)
    }

    pub(crate) fn record_fsp_decrypt_failure(&mut self, owner: OwnerId) -> Option<u32> {
        self.owner_shard_mut(owner)
            .record_fsp_decrypt_failure(owner)
    }

    pub(crate) fn submit_socket_packet(
        &mut self,
        packet: SocketPacket,
    ) -> Result<u64, AdmissionDrop> {
        let lane = packet.lane();
        if self.admission_lens.lane(lane) >= self.config.lane_capacity(lane) {
            let drop = AdmissionDrop::inbound(&packet);
            self.record_drop(drop.clone().into());
            return Err(drop);
        }

        let ingress_seq = self.next_ingress_seq();
        let shard = self.owner_shard_index(packet.owner);
        let lane_ready = self.shards[shard].submit_socket_packet_with_seq(packet, ingress_seq);
        self.admission_lens.increment(lane);
        if lane_ready {
            self.ingress_ready_shards.mark(shard, lane);
        }
        Ok(ingress_seq)
    }

    fn submit_socket_packet_batch(&mut self, packets: Vec<SocketPacket>) -> (usize, usize) {
        if let Some((owner, lane)) = socket_packet_run_owner_lane(&packets) {
            return self.submit_socket_packet_run(Some(owner), Some(lane), packets);
        }

        let mut admitted = 0usize;
        let mut dropped = 0usize;
        let mut run = Vec::new();
        let mut run_owner = None;
        let mut run_lane = None;

        for packet in packets {
            let owner = packet.owner;
            let lane = packet.lane();
            if run_owner == Some(owner) && run_lane == Some(lane) {
                run.push(packet);
                continue;
            }

            let (run_admitted, run_dropped) =
                self.submit_socket_packet_run(run_owner, run_lane, std::mem::take(&mut run));
            admitted = admitted.saturating_add(run_admitted);
            dropped = dropped.saturating_add(run_dropped);
            run_owner = Some(owner);
            run_lane = Some(lane);
            run.push(packet);
        }

        let (run_admitted, run_dropped) =
            self.submit_socket_packet_run(run_owner, run_lane, run);
        admitted = admitted.saturating_add(run_admitted);
        dropped = dropped.saturating_add(run_dropped);
        (admitted, dropped)
    }

    fn submit_socket_packet_run(
        &mut self,
        owner: Option<OwnerId>,
        lane: Option<Lane>,
        mut packets: Vec<SocketPacket>,
    ) -> (usize, usize) {
        let (Some(owner), Some(lane)) = (owner, lane) else {
            return (0, 0);
        };
        if packets.is_empty() {
            return (0, 0);
        }

        let available = self
            .config
            .lane_capacity(lane)
            .saturating_sub(self.admission_lens.lane(lane));
        let admitted = available.min(packets.len());
        let dropped_packets = packets.split_off(admitted);
        let dropped = dropped_packets.len();
        for packet in dropped_packets {
            let drop = AdmissionDrop::inbound(&packet);
            self.record_drop(drop.clone().into());
        }

        if admitted == 0 {
            return (0, dropped);
        }

        let first_seq = self.next_ingress_seq;
        self.next_ingress_seq = self.next_ingress_seq.wrapping_add(admitted as u64);
        let shard = self.owner_shard_index(owner);
        let lane_ready = self.shards[shard].submit_socket_packet_run_with_seq(packets, first_seq);
        self.admission_lens.increment_by(lane, admitted);
        if lane_ready {
            self.ingress_ready_shards.mark(shard, lane);
        }
        (admitted, dropped)
    }

    fn submit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
    ) -> Result<u64, AdmissionDrop> {
        let lane = packet.lane();
        if self.outbound_admission_lens.lane(lane) >= self.config.lane_capacity(lane) {
            let drop = AdmissionDrop::outbound(&packet);
            self.record_drop(drop.clone().into());
            return Err(drop);
        }

        let ingress_seq = self.next_outbound_seq();
        let shard = self.owner_shard_index(packet.owner);
        let lane_ready = self.shards[shard].submit_outbound_packet_with_seq(packet, ingress_seq);
        self.outbound_admission_lens.increment(lane);
        if lane_ready {
            self.outbound_ready_shards.mark(shard, lane);
        }
        Ok(ingress_seq)
    }

    fn submit_outbound_packet_batch(&mut self, packets: Vec<OutboundPacket>) -> (usize, usize) {
        if let Some((owner, lane)) = outbound_packet_run_owner_lane(&packets) {
            return self.submit_outbound_packet_run(Some(owner), Some(lane), packets);
        }

        let mut admitted = 0usize;
        let mut dropped = 0usize;
        let mut run = Vec::new();
        let mut run_owner = None;
        let mut run_lane = None;

        for packet in packets {
            let owner = packet.owner;
            let lane = packet.lane();
            if run_owner == Some(owner) && run_lane == Some(lane) {
                run.push(packet);
                continue;
            }

            let (run_admitted, run_dropped) = self.submit_outbound_packet_run(
                run_owner,
                run_lane,
                std::mem::take(&mut run),
            );
            admitted = admitted.saturating_add(run_admitted);
            dropped = dropped.saturating_add(run_dropped);
            run_owner = Some(owner);
            run_lane = Some(lane);
            run.push(packet);
        }

        let (run_admitted, run_dropped) =
            self.submit_outbound_packet_run(run_owner, run_lane, run);
        admitted = admitted.saturating_add(run_admitted);
        dropped = dropped.saturating_add(run_dropped);
        (admitted, dropped)
    }

    fn submit_outbound_packet_run(
        &mut self,
        owner: Option<OwnerId>,
        lane: Option<Lane>,
        mut packets: Vec<OutboundPacket>,
    ) -> (usize, usize) {
        let (Some(owner), Some(lane)) = (owner, lane) else {
            return (0, 0);
        };
        if packets.is_empty() {
            return (0, 0);
        }

        let available = self
            .config
            .lane_capacity(lane)
            .saturating_sub(self.outbound_admission_lens.lane(lane));
        let admitted = available.min(packets.len());
        let dropped_packets = packets.split_off(admitted);
        let dropped = dropped_packets.len();
        for packet in dropped_packets {
            let drop = AdmissionDrop::outbound(&packet);
            self.record_drop(drop.clone().into());
        }

        if admitted == 0 {
            return (0, dropped);
        }

        let first_seq = self.next_outbound_seq;
        self.next_outbound_seq = self.next_outbound_seq.wrapping_add(admitted as u64);
        let shard = self.owner_shard_index(owner);
        let lane_ready = self.shards[shard].submit_outbound_packet_run_with_seq(packets, first_seq);
        self.outbound_admission_lens.increment_by(lane, admitted);
        if lane_ready {
            self.outbound_ready_shards.mark(shard, lane);
        }
        (admitted, dropped)
    }

    fn queue_completion_batches(&mut self, batches: &mut Vec<CryptoCompletionBatch>) -> usize {
        let mut count = 0usize;
        for batch in batches.drain(..) {
            count = count.saturating_add(batch.len());
            self.queue_completion_run(batch);
        }
        count
    }

    fn queue_completion_run(&mut self, batch: CryptoCompletionBatch) {
        if batch.is_empty() {
            return;
        }
        let shard = batch.owner_shard();
        #[cfg(debug_assertions)]
        let expected_shard = self.owner_shard_index(batch.owner());
        let Some(retire_worker) = self.retire_workers.get_mut(shard) else {
            for completion in batch.into_completions() {
                let drop =
                    PacketDrop::from_completion(&completion, PacketDropReason::UnknownOwner, None);
                self.drops.push(drop);
            }
            return;
        };
        #[cfg(debug_assertions)]
        debug_assert_eq!(shard, expected_shard);
        if retire_worker.queue_completion_batch(batch) {
            self.completion_ready_shards.mark(shard);
        }
    }

    fn retire_queued_completions_into(
        &mut self,
        limit: usize,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        compact_endpoint_data: bool,
    ) -> usize {
        if limit == 0 || self.shards.is_empty() {
            return 0;
        }

        let mut retired_count = 0usize;
        while retired_count < limit {
            let ready_shards = self.completion_ready_shards.len();
            if ready_shards == 0 {
                break;
            }
            let shard_limit = dataplane_owner_shard_dispatch_quantum(
                limit.saturating_sub(retired_count),
                ready_shards,
            );
            let mut pass_retired = 0usize;
            for _ in 0..ready_shards {
                if retired_count >= limit {
                    break;
                }
                let Some(shard) = self.completion_ready_shards.pop() else {
                    break;
                };
                let (got, ingress_ready_after, outbound_ready_after, has_queued_completions) = {
                    let Some(owner_shard) = self.shards.get_mut(shard) else {
                        continue;
                    };
                    let Some(retire_worker) = self.retire_workers.get_mut(shard) else {
                        continue;
                    };
                    let got = retire_worker.retire_queued_completions_into(
                        owner_shard,
                        shard_limit.min(limit.saturating_sub(retired_count)),
                        retired,
                        &mut self.drops,
                        compact_endpoint_data,
                    );
                    (
                        got,
                        LaneLens::from_tuple(owner_shard.admission_ready_lens()),
                        LaneLens::from_tuple(owner_shard.outbound_admission_ready_lens()),
                        retire_worker.has_queued_completions(),
                    )
                };
                retired_count = retired_count.saturating_add(got);
                pass_retired = pass_retired.saturating_add(got);
                self.ingress_ready_shards
                    .mark_from_lens(shard, ingress_ready_after);
                self.outbound_ready_shards
                    .mark_from_lens(shard, outbound_ready_after);
                if has_queued_completions {
                    self.completion_ready_shards.mark(shard);
                }
            }
            if pass_retired == 0 {
                break;
            }
        }
        retired_count
    }

    fn run_aead_available_into_with_executor<E>(
        &mut self,
        limit: usize,
        buffers: DataplaneAeadRunBuffers<'_>,
        executor: &mut E,
        compact_endpoint_data: bool,
    ) -> usize
    where
        E: DataplaneCryptoExecutor,
    {
        let DataplaneAeadRunBuffers {
            prepared_work,
            completion_work,
            completion_batches,
            outputs,
            outbound_packets,
            fsp_authenticated_ingress,
            drops,
        } = buffers;
        prepared_work.clear();
        completion_work.clear();
        completion_batches.clear();
        let mut dispatched_total = 0usize;
        let record_fsp_path_open = crate::perf_profile::enabled();
        let mut fsp_path_open = 0u64;
        let mut fsp_path_open_bulk = 0u64;
        {
            let _owner_dispatch_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::DataplaneOwnerDispatch,
            );
            let open_capacity = executor.available_open_capacity();
            let seal_capacity = executor.available_seal_capacity();
            let direction_capacity = open_capacity.saturating_add(seal_capacity);
            let executor_capacity = executor.available_capacity().min(direction_capacity);
            let total_limit = limit.min(executor_capacity);
            if limit > 0 && executor_capacity == 0 {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DataplaneDispatchExecutorFull,
                );
            }
            let mut open_priority_capacity =
                total_limit.min(executor.available_open_capacity_for_lane(Lane::Priority));
            let seal_priority_capacity =
                total_limit.min(executor.available_seal_capacity_for_lane(Lane::Priority));
            let open_bulk_capacity =
                total_limit.min(executor.available_open_capacity_for_lane(Lane::Bulk));
            let seal_bulk_capacity =
                total_limit.min(executor.available_seal_capacity_for_lane(Lane::Bulk));
            let inbound_priority_pending = self.has_inbound_priority_pending();
            let priority_feed_capacity = total_limit.min(
                open_priority_capacity
                    .saturating_add(seal_priority_capacity),
            );
            let outbound_priority_reserve = outbound_priority_dispatch_limit(
                priority_feed_capacity,
                self.has_outbound_priority_pending(),
            );
            let pre_priority_inbound_limit = inbound_before_outbound_priority_limit(
                priority_feed_capacity,
                outbound_priority_reserve,
            )
            .min(open_priority_capacity);

            let pre_priority_inbound_dispatched = self.dispatch_prepared_ingress_shards_into(
                pre_priority_inbound_limit,
                prepared_work,
                false,
                record_fsp_path_open,
                &mut fsp_path_open,
                &mut fsp_path_open_bulk,
            );
            dispatched_total = dispatched_total.saturating_add(pre_priority_inbound_dispatched);
            open_priority_capacity =
                open_priority_capacity.saturating_sub(pre_priority_inbound_dispatched);

            let priority_outbound_limit = outbound_priority_reserve
                .min(total_limit.saturating_sub(dispatched_total))
                .min(seal_priority_capacity);
            let priority_outbound_dispatched = self.dispatch_outbound_prepared_shards_into(
                priority_outbound_limit,
                prepared_work,
                true,
            );
            dispatched_total = dispatched_total.saturating_add(priority_outbound_dispatched);

            let priority_inbound_limit = if inbound_priority_pending {
                open_priority_capacity.min(total_limit.saturating_sub(dispatched_total))
            } else {
                0
            };
            let priority_inbound_dispatched = self.dispatch_prepared_ingress_shards_into(
                priority_inbound_limit,
                prepared_work,
                true,
                record_fsp_path_open,
                &mut fsp_path_open,
                &mut fsp_path_open_bulk,
            );
            dispatched_total = dispatched_total.saturating_add(priority_inbound_dispatched);

            let bulk_dispatch_capacity = total_limit
                .saturating_sub(dispatched_total)
                .min(open_bulk_capacity);
            let bulk_inbound_start = prepared_work.len();
            let inbound_dispatched = self.dispatch_prepared_ingress_shards_into(
                bulk_dispatch_capacity,
                prepared_work,
                false,
                record_fsp_path_open,
                &mut fsp_path_open,
                &mut fsp_path_open_bulk,
            );
            dispatched_total = dispatched_total.saturating_add(inbound_dispatched);
            let outbound_start = prepared_work.len();
            let outbound_dispatched = self.dispatch_outbound_prepared_shards_into(
                total_limit
                    .saturating_sub(dispatched_total)
                    .min(seal_bulk_capacity),
                prepared_work,
                false,
            );
            dispatched_total = dispatched_total.saturating_add(outbound_dispatched);
            debug_assert!(dispatched_total <= total_limit);

            let leading_priority_seals = prepared_work[outbound_start..]
                .iter()
                .take_while(|work| work.lane() == Lane::Priority)
                .count();
            if leading_priority_seals > 0 {
                prepared_work[bulk_inbound_start..outbound_start + leading_priority_seals]
                    .rotate_right(leading_priority_seals);
            }
            if record_fsp_path_open {
                record_fsp_path_open_dispatch(fsp_path_open, fsp_path_open_bulk);
            }
        }

        {
            let _executor_submit_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::DataplaneExecutorSubmit,
            );
            execute_prepared_crypto_chunk(executor, prepared_work, completion_work);
        }
        {
            let _completion_queue_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::DataplaneCompletionQueue,
            );
            CryptoCompletionBatch::drain_completion_vec_into_batches(
                completion_work,
                completion_batches,
            );
            self.queue_completion_batches(completion_batches);
            let mut retired = DataplaneRetiredOutputSink::new(
                outputs,
                outbound_packets,
                fsp_authenticated_ingress,
            );
            self.retire_queued_completions_into(limit, &mut retired, compact_endpoint_data);
        }

        drops.append(&mut self.drops);
        dispatched_total
    }

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    fn owner_shard_index(&self, owner: OwnerId) -> usize {
        dataplane_owner_shard_index(owner, self.shards.len())
    }

    fn owner_shard(&self, owner: OwnerId) -> &DataplaneOwnerShard {
        &self.shards[self.owner_shard_index(owner)]
    }

    fn owner_shard_mut(&mut self, owner: OwnerId) -> &mut DataplaneOwnerShard {
        let shard = self.owner_shard_index(owner);
        &mut self.shards[shard]
    }

    fn record_drop(&mut self, drop: PacketDrop) {
        self.drops.push(drop);
    }

    fn next_ingress_seq(&mut self) -> u64 {
        let ingress_seq = self.next_ingress_seq;
        self.next_ingress_seq = self.next_ingress_seq.wrapping_add(1);
        ingress_seq
    }

    fn next_outbound_seq(&mut self) -> u64 {
        let ingress_seq = self.next_outbound_seq;
        self.next_outbound_seq = self.next_outbound_seq.wrapping_add(1);
        ingress_seq
    }

    fn has_inbound_priority_pending(&self) -> bool {
        self.admission_lens.priority > 0
    }

    fn has_outbound_priority_pending(&self) -> bool {
        self.outbound_admission_lens.priority > 0
    }

    fn has_priority_pending(&self) -> bool {
        self.has_inbound_priority_pending() || self.has_outbound_priority_pending()
    }

    fn dispatch_prepared_ingress_shards_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        priority_only: bool,
        record_fsp_path_open: bool,
        fsp_path_open: &mut u64,
        fsp_path_open_bulk: &mut u64,
    ) -> usize {
        if limit == 0 || self.shards.is_empty() {
            crate::perf_profile::record_dataplane_crypto_open_batch(0);
            return 0;
        }

        let start_len = prepared.len();
        let priority_only = priority_only || self.has_inbound_priority_pending();
        let mut dispatched = 0usize;
        while dispatched < limit {
            let ready_lanes = self.ingress_ready_shards.ready_len(priority_only);
            if ready_lanes == 0 {
                break;
            }
            let shard_limit = dataplane_ingress_owner_shard_dispatch_limit(
                limit.saturating_sub(dispatched),
                ready_lanes,
                priority_only,
            );
            let mut pass_dispatched = 0usize;
            for _ in 0..ready_lanes {
                if dispatched >= limit {
                    break;
                }
                let Some(shard) = self.ingress_ready_shards.pop(priority_only) else {
                    break;
                };
                let before = LaneLens::from_tuple(self.shards[shard].admission_queue_lens());
                let got = self.shards[shard].dispatch_ingress_prepared_into(
                    shard_limit.min(limit.saturating_sub(dispatched)),
                    prepared,
                    priority_only,
                    record_fsp_path_open,
                    fsp_path_open,
                    fsp_path_open_bulk,
                    &mut self.drops,
                );
                let after = LaneLens::from_tuple(self.shards[shard].admission_queue_lens());
                let ready_after = LaneLens::from_tuple(self.shards[shard].admission_ready_lens());
                self.admission_lens
                    .saturating_sub_assign(before.saturating_sub(after));
                self.ingress_ready_shards.mark_from_lens(shard, ready_after);
                dispatched = dispatched.saturating_add(got);
                pass_dispatched = pass_dispatched.saturating_add(got);
            }
            if pass_dispatched == 0 {
                break;
            }
        }
        crate::perf_profile::record_dataplane_crypto_open_batch(
            prepared.len().saturating_sub(start_len),
        );
        dispatched
    }

    fn dispatch_outbound_prepared_shards_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        priority_only: bool,
    ) -> usize {
        if limit == 0 || self.shards.is_empty() {
            crate::perf_profile::record_dataplane_crypto_seal_batch(0);
            return 0;
        }

        let priority_only = priority_only || self.has_outbound_priority_pending();
        let start_len = prepared.len();
        let mut dispatched = 0usize;
        while dispatched < limit {
            let ready_lanes = self.outbound_ready_shards.ready_len(priority_only);
            if ready_lanes == 0 {
                break;
            }
            let shard_limit = dataplane_owner_shard_dispatch_quantum(
                limit.saturating_sub(dispatched),
                ready_lanes,
            );
            let mut pass_dispatched = 0usize;
            for _ in 0..ready_lanes {
                if dispatched >= limit {
                    break;
                }
                let Some(shard) = self.outbound_ready_shards.pop(priority_only) else {
                    break;
                };
                let before = LaneLens::from_tuple(self.shards[shard].outbound_admission_queue_lens());
                let got = self.shards[shard].dispatch_outbound_prepared_into(
                    shard_limit.min(limit.saturating_sub(dispatched)),
                    prepared,
                    priority_only,
                    &mut self.drops,
                );
                let after = LaneLens::from_tuple(self.shards[shard].outbound_admission_queue_lens());
                let ready_after =
                    LaneLens::from_tuple(self.shards[shard].outbound_admission_ready_lens());
                self.outbound_admission_lens
                    .saturating_sub_assign(before.saturating_sub(after));
                self.outbound_ready_shards.mark_from_lens(shard, ready_after);
                dispatched = dispatched.saturating_add(got);
                pass_dispatched = pass_dispatched.saturating_add(got);
            }
            if pass_dispatched == 0 {
                break;
            }
        }

        crate::perf_profile::record_dataplane_crypto_seal_batch(
            prepared.len().saturating_sub(start_len),
        );
        dispatched.min(limit)
    }

}

impl DataplaneCompletionSink for Dataplane {
    fn push_completion_batch(&mut self, batch: CryptoCompletionBatch) {
        self.queue_completion_run(batch);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LaneLens {
    priority: usize,
    bulk: usize,
}

impl LaneLens {
    fn from_tuple(lens: (usize, usize)) -> Self {
        Self {
            priority: lens.0,
            bulk: lens.1,
        }
    }

    fn lane(self, lane: Lane) -> usize {
        match lane {
            Lane::Priority => self.priority,
            Lane::Bulk => self.bulk,
        }
    }

    fn increment(&mut self, lane: Lane) {
        self.increment_by(lane, 1);
    }

    fn increment_by(&mut self, lane: Lane, count: usize) {
        match lane {
            Lane::Priority => self.priority = self.priority.saturating_add(count),
            Lane::Bulk => self.bulk = self.bulk.saturating_add(count),
        }
    }

    fn saturating_sub(self, other: Self) -> Self {
        Self {
            priority: self.priority.saturating_sub(other.priority),
            bulk: self.bulk.saturating_sub(other.bulk),
        }
    }

    fn saturating_sub_assign(&mut self, other: Self) {
        self.priority = self.priority.saturating_sub(other.priority);
        self.bulk = self.bulk.saturating_sub(other.bulk);
    }
}

#[derive(Clone, Debug)]
struct ReadyShardQueue {
    queue: VecDeque<usize>,
    ready: Vec<bool>,
}

impl ReadyShardQueue {
    fn new(shards: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            ready: vec![false; shards],
        }
    }

    fn mark(&mut self, shard: usize) {
        let Some(is_ready) = self.ready.get_mut(shard) else {
            return;
        };
        if *is_ready {
            return;
        }
        *is_ready = true;
        self.queue.push_back(shard);
    }

    fn pop(&mut self) -> Option<usize> {
        loop {
            let shard = self.queue.pop_front()?;
            let Some(is_ready) = self.ready.get_mut(shard) else {
                continue;
            };
            if !*is_ready {
                continue;
            }
            *is_ready = false;
            return Some(shard);
        }
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn has_ready(&self) -> bool {
        !self.queue.is_empty()
    }
}

#[derive(Clone, Debug)]
struct ReadyShardQueues {
    priority: ReadyShardQueue,
    bulk: ReadyShardQueue,
}

impl ReadyShardQueues {
    fn new(shards: usize) -> Self {
        Self {
            priority: ReadyShardQueue::new(shards),
            bulk: ReadyShardQueue::new(shards),
        }
    }

    fn mark(&mut self, shard: usize, lane: Lane) {
        self.lane_mut(lane).mark(shard);
    }

    fn mark_from_lens(&mut self, shard: usize, lens: LaneLens) {
        if lens.priority > 0 {
            self.mark(shard, Lane::Priority);
        }
        if lens.bulk > 0 {
            self.mark(shard, Lane::Bulk);
        }
    }

    fn pop(&mut self, priority_only: bool) -> Option<usize> {
        self.pop_lane(Lane::Priority).or_else(|| {
            if priority_only {
                None
            } else {
                self.pop_lane(Lane::Bulk)
            }
        })
    }

    fn ready_len(&self, priority_only: bool) -> usize {
        if priority_only {
            self.priority.len()
        } else {
            self.priority.len().saturating_add(self.bulk.len())
        }
    }

    fn has_ready(&self) -> bool {
        self.priority.has_ready() || self.bulk.has_ready()
    }

    fn pop_lane(&mut self, lane: Lane) -> Option<usize> {
        self.lane_mut(lane).pop()
    }

    fn lane_mut(&mut self, lane: Lane) -> &mut ReadyShardQueue {
        match lane {
            Lane::Priority => &mut self.priority,
            Lane::Bulk => &mut self.bulk,
        }
    }
}

fn record_ingress_owner_blocked(reason: Option<OwnerReserveBlockReason>) {
    record_owner_blocked(
        crate::perf_profile::Event::DataplaneDispatchIngressOwnerBlocked,
        reason,
    );
}

fn record_outbound_owner_blocked(reason: Option<OwnerReserveBlockReason>) {
    record_owner_blocked(
        crate::perf_profile::Event::DataplaneDispatchOutboundOwnerBlocked,
        reason,
    );
}

fn record_owner_blocked(
    source_event: crate::perf_profile::Event,
    reason: Option<OwnerReserveBlockReason>,
) {
    use crate::perf_profile::{record_event, Event};

    record_event(Event::DataplaneDispatchOwnerBlocked);
    record_event(source_event);
    match reason {
        Some(OwnerReserveBlockReason::TotalInFlight) => {
            record_event(Event::DataplaneDispatchOwnerBlockedTotal);
        }
        Some(OwnerReserveBlockReason::BulkLane) => {
            record_event(Event::DataplaneDispatchOwnerBlockedBulkLane);
        }
        None => {}
    }
}

fn execute_prepared_crypto_chunk<E>(
    executor: &mut E,
    prepared: &mut Vec<PreparedCryptoWork>,
    completions: &mut Vec<CryptoCompletion>,
) -> usize
where
    E: DataplaneCryptoExecutor,
{
    let prepared_len = prepared.len();
    let accepted = executor.execute_prepared_chunk(prepared, completions);
    debug_assert_eq!(
        accepted, prepared_len,
        "dataplane crypto executor must accept an entire owner-reserved prepared chunk"
    );
    accepted
}

fn socket_packet_run_owner_lane(packets: &[SocketPacket]) -> Option<(OwnerId, Lane)> {
    let first = packets.first()?;
    let owner = first.owner;
    let lane = first.lane();
    packets
        .iter()
        .all(|packet| packet.owner == owner && packet.lane() == lane)
        .then_some((owner, lane))
}

fn outbound_packet_run_owner_lane(packets: &[OutboundPacket]) -> Option<(OwnerId, Lane)> {
    let first = packets.first()?;
    let owner = first.owner;
    let lane = first.lane();
    packets
        .iter()
        .all(|packet| packet.owner == owner && packet.lane() == lane)
        .then_some((owner, lane))
}

fn outbound_priority_dispatch_limit(limit: usize, has_priority_pending: bool) -> usize {
    if !has_priority_pending || limit == 0 {
        return 0;
    }

    limit.min((limit / 32).max(1)).min(8)
}

fn inbound_before_outbound_priority_limit(limit: usize, outbound_priority_reserve: usize) -> usize {
    if outbound_priority_reserve == 0 {
        return 0;
    }

    limit.saturating_sub(outbound_priority_reserve).min(1)
}

fn count_fsp_path_open_dispatch(
    reservation: &OwnerReservation,
    total: &mut u64,
    bulk: &mut u64,
) {
    if reservation.owner.protocol() != PacketProtocol::Fsp {
        return;
    }

    *total += 1;
    if reservation.lane == Lane::Bulk {
        *bulk += 1;
    }
}

fn record_fsp_path_open_dispatch(total: u64, bulk: u64) {
    if total == 0 {
        return;
    }

    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DataplaneFspPathOpen,
        total,
    );
    if bulk > 0 {
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneFspPathOpenBulk,
            bulk,
        );
    }
}

fn dataplane_owner_shard_count(config: AdmissionConfig) -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
        .min(usize::BITS as usize)
        .min(config.total_capacity().max(1))
        .max(1)
}

fn dataplane_owner_shard_dispatch_quantum(remaining: usize, shard_count: usize) -> usize {
    let shard_count = shard_count.max(1);
    remaining.saturating_add(shard_count - 1) / shard_count
}

fn dataplane_ingress_owner_shard_dispatch_limit(
    remaining: usize,
    ready_lanes: usize,
    priority_only: bool,
) -> usize {
    if priority_only {
        dataplane_owner_shard_dispatch_quantum(remaining, ready_lanes)
    } else {
        remaining
    }
}

fn dataplane_owner_shard_index(owner: OwnerId, shards: usize) -> usize {
    let shards = shards.max(1);
    // NodeAddr is SHA-256-derived, so its bytes are already suitable for sharding.
    let node = u128::from_le_bytes(*owner.node_addr().as_bytes());
    let mixed = node ^ (node >> 64);
    (mixed as usize) % shards
}
