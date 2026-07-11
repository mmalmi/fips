#[derive(Debug)]
pub(crate) struct Dataplane {
    config: AdmissionConfig,
    shards: Vec<DataplaneOwnerShard>,
    admission_lens: LaneLens,
    outbound_admission_lens: LaneLens,
    drops: Vec<PacketDrop>,
    orphaned_slots: VecDeque<OwnerRetireSlot>,
    next_ingress_seq: u64,
    next_outbound_seq: u64,
    ingress_ready_shards: ReadyShardQueues,
    outbound_ready_shards: ReadyShardQueues,
    pending_retire_shards: ReadyShardQueue,
}

pub(crate) struct DataplaneAeadRunBuffers<'a> {
    prepared_work: &'a mut Vec<PreparedCryptoRun>,
    ready_slots: &'a mut Vec<Arc<CryptoReadySlot>>,
    outputs: &'a mut Vec<PacketOutput>,
    outbound_packets: &'a mut Vec<OutboundPacket>,
    fsp_authenticated_ingress: &'a mut DataplaneFspAuthenticatedIngress,
    drops: &'a mut Vec<PacketDrop>,
}

impl<'a> DataplaneAeadRunBuffers<'a> {
    pub(crate) fn new(
        prepared_work: &'a mut Vec<PreparedCryptoRun>,
        ready_slots: &'a mut Vec<Arc<CryptoReadySlot>>,
        outputs: &'a mut Vec<PacketOutput>,
        outbound_packets: &'a mut Vec<OutboundPacket>,
        fsp_authenticated_ingress: &'a mut DataplaneFspAuthenticatedIngress,
        drops: &'a mut Vec<PacketDrop>,
    ) -> Self {
        Self {
            prepared_work,
            ready_slots,
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
        Self {
            config,
            shards,
            admission_lens: LaneLens::default(),
            outbound_admission_lens: LaneLens::default(),
            drops: Vec::new(),
            orphaned_slots: VecDeque::new(),
            next_ingress_seq: 0,
            next_outbound_seq: 0,
            ingress_ready_shards: ReadyShardQueues::new(shard_count),
            outbound_ready_shards: ReadyShardQueues::new(shard_count),
            pending_retire_shards: ReadyShardQueue::new(shard_count.saturating_add(1)),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        let shard = self.owner_shard_index(owner);
        let orphaned = self.shards[shard].register_owner(owner, config);
        if !orphaned.is_empty() {
            self.orphaned_slots.extend(orphaned);
            self.pending_retire_shards.mark(self.shards.len(), false);
        }
        self.mark_admission_ready_shard(shard);
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> bool {
        let shard = self.owner_shard_index(owner);
        let Some(orphaned) = self.shards[shard].unregister_owner(owner) else {
            return false;
        };
        if !orphaned.is_empty() {
            self.orphaned_slots.extend(orphaned);
            self.pending_retire_shards.mark(self.shards.len(), false);
        }
        self.mark_admission_ready_shard(shard);
        true
    }

    pub(crate) fn has_owner(&self, owner: OwnerId) -> bool {
        self.owner_shard(owner).has_owner(owner)
    }

    pub(crate) fn has_runnable_work(&self) -> bool {
        self.ingress_ready_shards.has_ready()
            || self.outbound_ready_shards.has_ready()
            || self
                .shards
                .iter()
                .any(DataplaneOwnerShard::has_ready_retirements)
            || self.orphaned_slots.iter().any(OwnerRetireSlot::is_ready)
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
        let owner = packet.owner;
        let shard = self.owner_shard_index(owner);
        let lane_ready = self.shards[shard].submit_socket_packet_with_seq(packet, ingress_seq);
        self.admission_lens.increment(lane);
        if lane_ready {
            self.ingress_ready_shards.mark_owner(shard, lane, owner);
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
            self.ingress_ready_shards.mark_owner(shard, lane, owner);
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
        let owner = packet.owner;
        let shard = self.owner_shard_index(owner);
        let lane_ready = self.shards[shard].submit_outbound_packet_with_seq(packet, ingress_seq);
        self.outbound_admission_lens.increment(lane);
        if lane_ready {
            self.outbound_ready_shards.mark_owner(shard, lane, owner);
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
            self.outbound_ready_shards.mark_owner(shard, lane, owner);
        }
        (admitted, dropped)
    }

    fn stage_retire_slots(&mut self, slots: &mut Vec<Arc<CryptoReadySlot>>) {
        for slot in slots.drain(..) {
            self.stage_retire_slot(slot);
        }
    }

    fn stage_retire_slot(&mut self, slot: Arc<CryptoReadySlot>) {
        let shard = slot.owner_shard();
        #[cfg(debug_assertions)]
        debug_assert_eq!(shard, self.owner_shard_index(slot.owner()));
        let Some(owner_shard) = self.shards.get_mut(shard) else {
            self.orphaned_slots.push_back(OwnerRetireSlot::new(slot));
            self.pending_retire_shards.mark(self.shards.len(), false);
            return;
        };
        match owner_shard.stage_retire_slot(slot) {
            Ok(()) => self.pending_retire_shards.mark(shard, false),
            Err(slot) => {
                self.orphaned_slots.push_back(OwnerRetireSlot::new(slot));
                self.pending_retire_shards.mark(self.shards.len(), false);
            }
        }
    }

    fn retire_ready_slots_into(
        &mut self,
        limit: usize,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        compact_endpoint_data: bool,
    ) -> usize {
        if limit == 0 {
            return 0;
        }

        let mut retired_count = 0usize;
        let sources_to_scan = self.pending_retire_shards.len();
        let orphan_source = self.shards.len();
        for remaining_sources in (1..=sources_to_scan).rev() {
            if retired_count >= limit {
                break;
            }
            let Some(source) = self.pending_retire_shards.pop() else {
                break;
            };
            let source_limit = limit
                .saturating_sub(retired_count)
                .div_ceil(remaining_sources);
            if source == orphan_source {
                let got = self.retire_ready_orphan_slots_into(source_limit);
                retired_count = retired_count.saturating_add(got);
                if !self.orphaned_slots.is_empty() {
                    self.pending_retire_shards.mark(orphan_source, false);
                }
                continue;
            }
            let Some(owner_shard) = self.shards.get_mut(source) else {
                continue;
            };
            let got = owner_shard.retire_ready_slots_into(
                source_limit,
                retired,
                &mut self.drops,
                compact_endpoint_data,
            );
            let has_pending = owner_shard.has_pending_retirements();
            retired_count = retired_count.saturating_add(got);
            self.mark_admission_ready_shard(source);
            if has_pending {
                self.pending_retire_shards.mark(source, false);
            }
        }
        retired_count
    }

    fn retire_ready_orphan_slots_into(&mut self, limit: usize) -> usize {
        let mut retired_count = 0usize;
        let orphans_to_scan = self.orphaned_slots.len();
        for _ in 0..orphans_to_scan {
            if retired_count >= limit {
                break;
            }
            let Some(mut slot) = self.orphaned_slots.pop_front() else {
                break;
            };
            if !slot.is_ready() {
                self.orphaned_slots.push_back(slot);
                continue;
            }
            let got = slot.drain_results(
                limit.saturating_sub(retired_count).min(slot.remaining()),
                |completion| {
                    self.drops.push(PacketDrop::from_completion(
                        &completion,
                        PacketDropReason::UnknownOwner,
                        None,
                    ));
                },
            );
            retired_count = retired_count.saturating_add(got);
            if !slot.is_empty() {
                self.orphaned_slots.push_back(slot);
            }
        }
        retired_count
    }

    fn run_aead_available_into(
        &mut self,
        limit: usize,
        buffers: DataplaneAeadRunBuffers<'_>,
        worker_pool: &mut DataplaneAeadWorkerPool,
        compact_endpoint_data: bool,
    ) -> usize {
        let DataplaneAeadRunBuffers {
            prepared_work,
            ready_slots,
            outputs,
            outbound_packets,
            fsp_authenticated_ingress,
            drops,
        } = buffers;
        let dispatched_total = self.prepare_aead_available_into(
            limit,
            prepared_work,
            ready_slots,
            worker_pool,
        );

        self.stage_retire_slots(ready_slots);
        {
            let _executor_submit_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::DataplaneExecutorSubmit,
            );
            worker_pool.submit_prepared_chunk(prepared_work, |slot| {
                self.stage_retire_slot(slot);
            });
        }
        {
            let _completion_queue_timer = crate::perf_profile::Timer::start(
                crate::perf_profile::Stage::DataplaneCompletionQueue,
            );
            let mut retired = DataplaneRetiredOutputSink::new(
                outputs,
                outbound_packets,
                fsp_authenticated_ingress,
            );
            self.retire_ready_slots_into(limit, &mut retired, compact_endpoint_data);
        }

        drops.append(&mut self.drops);
        dispatched_total
    }

    fn prepare_aead_available_into(
        &mut self,
        limit: usize,
        prepared_work: &mut Vec<PreparedCryptoRun>,
        ready_slots: &mut Vec<Arc<CryptoReadySlot>>,
        worker_pool: &DataplaneAeadWorkerPool,
    ) -> usize {
        prepared_work.clear();
        ready_slots.clear();
        let _owner_dispatch_timer = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::DataplaneOwnerDispatch,
        );
        let worker_capacity = worker_pool.available_capacity();
        let total_limit = limit.min(worker_capacity);
        if limit > 0 && worker_capacity == 0 {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DataplaneDispatchExecutorFull,
            );
        }
        let priority_capacity =
            total_limit.min(worker_pool.available_capacity_for_lane(Lane::Priority));
        let mut priority_inbound_capacity = priority_capacity;
        let bulk_capacity = total_limit.min(worker_pool.available_capacity_for_lane(Lane::Bulk));
        let inbound_priority_pending = self.has_inbound_priority_pending();
        let outbound_priority_reserve = outbound_priority_dispatch_limit(
            priority_capacity,
            self.has_outbound_priority_pending(),
        );
        let pre_priority_inbound_limit = inbound_before_outbound_priority_limit(
            priority_capacity,
            outbound_priority_reserve,
        )
        .min(priority_inbound_capacity);
        let mut fsp_path_open = FspPathOpenDispatch::new(crate::perf_profile::enabled());

        let mut dispatched_total = self.dispatch_prepared_ingress_shards_into(
            pre_priority_inbound_limit,
            prepared_work,
            ready_slots,
            false,
            &mut fsp_path_open,
        );
        priority_inbound_capacity =
            priority_inbound_capacity.saturating_sub(dispatched_total);

        let priority_outbound_limit =
            outbound_priority_reserve.min(total_limit.saturating_sub(dispatched_total));
        dispatched_total = dispatched_total.saturating_add(
            self.dispatch_outbound_prepared_shards_into(
                priority_outbound_limit,
                prepared_work,
                ready_slots,
                true,
            ),
        );

        let priority_inbound_limit = if inbound_priority_pending {
            priority_inbound_capacity.min(total_limit.saturating_sub(dispatched_total))
        } else {
            0
        };
        dispatched_total = dispatched_total.saturating_add(
            self.dispatch_prepared_ingress_shards_into(
                priority_inbound_limit,
                prepared_work,
                ready_slots,
                true,
                &mut fsp_path_open,
            ),
        );

        let bulk_dispatch_capacity = total_limit
            .saturating_sub(dispatched_total)
            .min(bulk_capacity);
        let bulk_inbound_start = prepared_work.len();
        dispatched_total = dispatched_total.saturating_add(
            self.dispatch_prepared_ingress_shards_into(
                bulk_dispatch_capacity,
                prepared_work,
                ready_slots,
                false,
                &mut fsp_path_open,
            ),
        );
        let outbound_start = prepared_work.len();
        dispatched_total = dispatched_total.saturating_add(
            self.dispatch_outbound_prepared_shards_into(
                total_limit.saturating_sub(dispatched_total).min(bulk_capacity),
                prepared_work,
                ready_slots,
                false,
            ),
        );
        debug_assert!(dispatched_total <= total_limit);

        let leading_priority_seals = prepared_work[outbound_start..]
            .iter()
            .take_while(|work| work.lane() == Lane::Priority)
            .count();
        if leading_priority_seals > 0 {
            prepared_work[bulk_inbound_start..outbound_start + leading_priority_seals]
                .rotate_right(leading_priority_seals);
        }
        fsp_path_open.record();
        dispatched_total
    }

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    fn owner_shard_index(&self, owner: OwnerId) -> usize {
        dataplane_owner_shard_index(owner, self.shards.len())
    }

    fn mark_admission_ready_shard(&mut self, shard: usize) {
        let ingress = LaneLens::from_tuple(self.shards[shard].admission_ready_lens());
        let outbound = LaneLens::from_tuple(self.shards[shard].outbound_admission_ready_lens());
        self.ingress_ready_shards.mark_from_lens(shard, ingress);
        self.outbound_ready_shards.mark_from_lens(shard, outbound);
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
        prepared: &mut Vec<PreparedCryptoRun>,
        ready_slots: &mut Vec<Arc<CryptoReadySlot>>,
        priority_only: bool,
        fsp_path_open: &mut FspPathOpenDispatch,
    ) -> usize {
        if limit == 0 || self.shards.is_empty() {
            crate::perf_profile::record_dataplane_crypto_open_batch(0);
            return 0;
        }

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
                    ready_slots,
                    priority_only,
                    fsp_path_open,
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
        crate::perf_profile::record_dataplane_crypto_open_batch(dispatched);
        dispatched
    }

    fn dispatch_outbound_prepared_shards_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoRun>,
        ready_slots: &mut Vec<Arc<CryptoReadySlot>>,
        priority_only: bool,
    ) -> usize {
        if limit == 0 || self.shards.is_empty() {
            crate::perf_profile::record_dataplane_crypto_seal_batch(0);
            return 0;
        }

        let priority_only = priority_only || self.has_outbound_priority_pending();
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
                    ready_slots,
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

        crate::perf_profile::record_dataplane_crypto_seal_batch(dispatched);
        dispatched.min(limit)
    }

}
