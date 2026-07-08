#[derive(Debug)]
struct DataplaneOwnerShardRetireWorker {
    completed: VecDeque<CryptoCompletionBatch>,
}

impl DataplaneOwnerShardRetireWorker {
    fn new() -> Self {
        Self {
            completed: VecDeque::new(),
        }
    }

    fn queue_completion_batch(&mut self, batch: CryptoCompletionBatch) -> bool {
        if batch.is_empty() {
            return false;
        }
        let was_empty = self.completed.is_empty();
        self.completed.push_back(batch);
        was_empty
    }

    fn retire_queued_completions_into(
        &mut self,
        owner_shard: &mut DataplaneOwnerShard,
        limit: usize,
        retired: &mut Vec<RetiredOutputs>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) -> usize {
        let mut retired_count = 0usize;
        while retired_count < limit {
            let Some(mut batch) = self.completed.pop_front() else {
                break;
            };
            let batch_limit = limit.saturating_sub(retired_count);
            let pending = if batch.len() > batch_limit {
                Some(batch.split_off(batch_limit))
            } else {
                None
            };
            let batch_len = batch.len();
            owner_shard.retire_completion_batch_into(
                batch,
                retired,
                drops,
                compact_endpoint_data,
            );
            retired_count = retired_count.saturating_add(batch_len);
            if let Some(pending) = pending {
                self.completed.push_front(pending);
                break;
            }
        }
        retired_count
    }

    fn has_queued_completions(&self) -> bool {
        !self.completed.is_empty()
    }
}

#[derive(Debug)]
struct DataplaneOwnerShard {
    index: usize,
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
}

impl DataplaneOwnerShard {
    fn new(index: usize) -> Self {
        Self {
            index,
            admission: AdmissionQueue::new(),
            outbound_admission: OutboundAdmissionQueue::new(),
            owners: HashMap::new(),
        }
    }

    fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.owners.insert(owner, OwnerState::new(owner, config));
    }

    fn unregister_owner(&mut self, owner: OwnerId) -> bool {
        self.owners.remove(&owner).is_some()
    }

    fn has_owner(&self, owner: OwnerId) -> bool {
        self.owners.contains_key(&owner)
    }

    fn fsp_owner_destinations(&self, destinations: &mut Vec<NodeAddr>) {
        destinations.extend(self.owners.keys().filter_map(|owner| {
            (owner.protocol() == PacketProtocol::Fsp).then_some(owner.node_addr())
        }));
    }

    fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.owners
            .get(&owner)
            .and_then(OwnerState::active_path)
    }

    fn owner_fsp_next_hop(&self, owner: OwnerId) -> Option<NodeAddr> {
        self.owners
            .get(&owner)
            .and_then(OwnerState::fsp_wrap_next_hop)
    }

    fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owners.get_mut(&owner)
    }

    fn owner(&self, owner: OwnerId) -> Option<&OwnerState> {
        self.owners.get(&owner)
    }

    fn owner_fsp_activity(&self, owner: OwnerId) -> Option<DataplaneFspOwnerActivity> {
        self.owner(owner).and_then(OwnerState::fsp_activity)
    }

    fn owner_has_fsp_pending_receive_epoch(
        &self,
        owner: OwnerId,
        received_k_bit: bool,
    ) -> bool {
        self.owner(owner)
            .is_some_and(|owner| owner.has_fsp_pending_receive_epoch(received_k_bit))
    }

    fn owner_has_fmp_pending_receive_epoch(
        &self,
        owner: OwnerId,
        received_k_bit: bool,
    ) -> bool {
        self.owner(owner)
            .is_some_and(|owner| owner.has_fmp_pending_receive_epoch(received_k_bit))
    }

    fn owner_fsp_mmp_snapshot(&self, owner: OwnerId) -> Option<DataplaneFspMmpSnapshot> {
        self.owner(owner).and_then(OwnerState::fsp_mmp_snapshot)
    }

    fn owner_fsp_send_context(&self, owner: OwnerId) -> Option<DataplaneFspSendContext> {
        self.owner(owner).and_then(OwnerState::fsp_send_context)
    }

    fn owner_fmp_send_context(&self, owner: OwnerId) -> Option<DataplaneFmpSendContext> {
        self.owner(owner).and_then(OwnerState::fmp_send_context)
    }

    fn owner_fmp_link_metrics(
        &self,
        owner: OwnerId,
        now: std::time::Instant,
    ) -> Option<DataplaneFmpLinkMetrics> {
        self.owner(owner)
            .and_then(|owner| owner.fmp_link_metrics(now))
    }

    fn owner_fmp_link_cost(&self, owner: OwnerId) -> Option<f64> {
        self.owner(owner).and_then(OwnerState::fmp_link_cost)
    }

    fn owner_fmp_has_srtt(&self, owner: OwnerId) -> bool {
        self.owner(owner).is_some_and(OwnerState::fmp_has_srtt)
    }

    fn collect_fmp_mmp_reports(
        &mut self,
        now: std::time::Instant,
        batch: &mut DataplaneFmpMmpReportBatch,
    ) {
        for owner in self.owners.values_mut() {
            owner.collect_fmp_mmp_reports(now, batch);
        }
    }

    fn collect_fsp_mmp_reports(
        &mut self,
        now: std::time::Instant,
        batch: &mut DataplaneFspMmpReportBatch,
    ) {
        for owner in self.owners.values_mut() {
            owner.collect_fsp_mmp_reports(now, batch);
        }
    }

    fn record_fsp_mmp_send_result(
        &mut self,
        owner: OwnerId,
        success: bool,
    ) -> Option<DataplaneFspMmpReportingResumed> {
        self.owner_mut(owner)
            .and_then(|owner| owner.record_fsp_mmp_send_result(success))
    }

    fn seed_fsp_path_mtu(
        &mut self,
        owner: OwnerId,
        path_mtu: u16,
    ) -> Result<(), DataplaneFspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(DataplaneFspMmpSkip::UnknownOwner)?
            .seed_fsp_path_mtu(path_mtu)
    }

    fn process_fsp_mmp_receiver_report(
        &mut self,
        owner: OwnerId,
        rr: &crate::mmp::report::ReceiverReport,
        last_outbound_next_hop: Option<NodeAddr>,
        now_ms: u64,
        now: std::time::Instant,
        min_loss_sample: u64,
    ) -> Result<DataplaneFspReceiverReportResult, DataplaneFspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(DataplaneFspMmpSkip::UnknownOwner)?
            .process_fsp_mmp_receiver_report(
                rr,
                last_outbound_next_hop,
                now_ms,
                now,
                min_loss_sample,
            )
    }

    fn apply_fsp_path_mtu_signal(
        &mut self,
        owner: OwnerId,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<DataplaneFspPathMtuApplyResult, DataplaneFspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(DataplaneFspMmpSkip::UnknownOwner)?
            .apply_fsp_path_mtu_signal(path_mtu, now)
    }

    fn min_fsp_rx_age_for_next_hop(&self, next_hop: &NodeAddr, now_ms: u64) -> Option<u64> {
        self.owners
            .values()
            .filter_map(OwnerState::fsp_activity)
            .filter(|activity| activity.tracks_next_hop(next_hop))
            .filter_map(|activity| activity.last_rx_age_ms(now_ms))
            .min()
    }

    fn min_fsp_data_rx_age_for_next_hop(&self, next_hop: &NodeAddr, now_ms: u64) -> Option<u64> {
        self.owners
            .values()
            .filter_map(OwnerState::fsp_activity)
            .filter(|activity| activity.tracks_data_next_hop(next_hop))
            .filter_map(|activity| activity.last_rx_data_age_ms(now_ms))
            .min()
    }

    fn any_fsp_recent_outbound_without_inbound_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
        timeout_ms: u64,
    ) -> bool {
        self.owners
            .values()
            .filter_map(OwnerState::fsp_activity)
            .filter(|activity| activity.tracks_next_hop(next_hop))
            .any(|activity| activity.has_recent_outbound_without_inbound(now_ms, timeout_ms))
    }

    fn submit_socket_packet_with_seq(
        &mut self,
        packet: SocketPacket,
        ingress_seq: u64,
    ) -> bool {
        self.admission.admit_with_seq(packet, ingress_seq)
    }

    fn submit_socket_packet_run_with_seq(
        &mut self,
        packets: Vec<SocketPacket>,
        first_seq: u64,
    ) -> bool {
        self.admission.admit_run_with_seq(packets, first_seq)
    }

    fn submit_outbound_packet_with_seq(
        &mut self,
        packet: OutboundPacket,
        ingress_seq: u64,
    ) -> bool {
        self.outbound_admission.admit_with_seq(packet, ingress_seq)
    }

    fn submit_outbound_packet_run_with_seq(
        &mut self,
        packets: Vec<OutboundPacket>,
        first_seq: u64,
    ) -> bool {
        self.outbound_admission
            .admit_run_with_seq(packets, first_seq)
    }

    fn dispatch_ingress_prepared_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        priority_only: bool,
        fsp_path_open: &mut u64,
        fsp_path_open_bulk: &mut u64,
        drops: &mut Vec<PacketDrop>,
    ) -> usize {
        let mut dispatched = 0usize;
        let mut attempts_remaining = self.admission.len();
        while dispatched < limit && attempts_remaining > 0 {
            let run_limit = limit.saturating_sub(dispatched);
            let Some(mut run) = self.admission.pop_next_run(priority_only, run_limit) else {
                if !priority_only && limit > 0 {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::DataplaneDispatchNoIngress,
                    );
                }
                break;
            };
            attempts_remaining = attempts_remaining.saturating_sub(run.items.len());
            if run.items.len() > 1 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::DataplaneIngressOwnerRunContinue,
                    run.items.len().saturating_sub(1) as u64,
                );
            }
            let owner_id = run.cursor.owner;

            let Some(owner) = self.owners.get_mut(&owner_id) else {
                for queued in &run.items {
                    drops.push(PacketDrop::from_queued(
                        queued,
                        PacketDropReason::UnknownOwner,
                    ));
                }
                self.admission.continue_owner_lane(run.cursor);
                continue;
            };

            let mut remaining = Vec::new();
            let mut items = std::mem::take(&mut run.items).into_iter();
            while let Some(queued) = items.next() {
                if !owner.can_reserve_class(queued.packet.class) {
                    record_ingress_owner_blocked(owner.reserve_block_reason(queued.packet.class));
                    remaining.push(queued);
                    remaining.extend(items);
                    break;
                }

                match owner.reserve(&queued.packet, queued.ingress_seq) {
                    Ok((reservation, open_key)) => {
                        let reservation = reservation.with_owner_shard(self.index);
                        count_fsp_path_open_dispatch(
                            &reservation,
                            fsp_path_open,
                            fsp_path_open_bulk,
                        );
                        let prepared_work = match open_key {
                            Some(open_key) => PreparedCryptoWork::open(
                                CryptoWork {
                                    reservation,
                                    packet: queued.packet,
                                },
                                open_key,
                            ),
                            None => {
                                PreparedCryptoWork::failed(reservation, CryptoFailureKind::Open)
                            }
                        };
                        prepared.push(prepared_work);
                        dispatched = dispatched.saturating_add(1);
                        attempts_remaining = self.admission.len();
                    }
                    Err(error) => {
                        drops.push(PacketDrop::from_queued(&queued, error.into()));
                    }
                }
            }

            if remaining.is_empty() {
                self.admission.continue_owner_lane(run.cursor);
            } else {
                run.items = remaining;
                self.admission.defer_owner_run(run);
            }
        }

        if !priority_only && limit > 0 && dispatched >= limit {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DataplaneDispatchLimitHit,
            );
        }
        dispatched
    }

    fn dispatch_outbound_prepared_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        priority_only: bool,
        drops: &mut Vec<PacketDrop>,
    ) -> usize {
        let start_len = prepared.len();
        let target_len = start_len.saturating_add(limit);
        let mut attempts_remaining = self.outbound_admission.len();
        while prepared.len() < target_len && attempts_remaining > 0 {
            let run_limit = target_len.saturating_sub(prepared.len());
            let Some(mut run) = self
                .outbound_admission
                .pop_next_run(priority_only, run_limit)
            else {
                break;
            };
            attempts_remaining = attempts_remaining.saturating_sub(run.items.len());
            if run.items.len() > 1 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::DataplaneOutboundOwnerRunContinue,
                    run.items.len().saturating_sub(1) as u64,
                );
            }
            let owner_id = run.cursor.owner;

            let Some(owner) = self.owners.get_mut(&owner_id) else {
                for queued in &run.items {
                    drops.push(PacketDrop::from_queued_outbound(
                        queued,
                        PacketDropReason::UnknownOwner,
                    ));
                }
                self.outbound_admission.continue_owner_lane(run.cursor);
                continue;
            };

            let mut remaining = Vec::new();
            let mut items = std::mem::take(&mut run.items).into_iter();
            while let Some(queued) = items.next() {
                let class = queued.packet.class;
                let ingress_seq = queued.ingress_seq;
                if !owner.can_reserve_class(class) {
                    record_outbound_owner_blocked(owner.reserve_block_reason(class));
                    remaining.push(queued);
                    remaining.extend(items);
                    break;
                }

                match owner.reserve_outbound(queued.packet, ingress_seq) {
                    Ok((reservation, packet)) => {
                        let reservation = reservation.with_owner_shard(self.index);
                        let prepared_work = match owner.seal_key() {
                            Some(seal_key) => PreparedCryptoWork::seal(
                                OutboundCryptoWork {
                                    reservation,
                                    packet,
                                },
                                seal_key,
                            ),
                            None => {
                                PreparedCryptoWork::failed(reservation, CryptoFailureKind::Seal)
                            }
                        };
                        prepared.push(prepared_work);
                    }
                    Err(error) => {
                        drops.push(PacketDrop {
                            owner: owner_id,
                            counter: None,
                            reason: error.into(),
                            crypto_failure: None,
                            wire_flags: None,
                            authenticated_counter_highest: None,
                        });
                    }
                }
                attempts_remaining = self.outbound_admission.len();
            }

            if remaining.is_empty() {
                self.outbound_admission.continue_owner_lane(run.cursor);
            } else {
                run.items = remaining;
                self.outbound_admission.defer_owner_run(run);
            }
        }
        prepared.len().saturating_sub(start_len)
    }

    pub(crate) fn retire_completion_batch_into(
        &mut self,
        batch: CryptoCompletionBatch,
        retired: &mut Vec<RetiredOutputs>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneRetire);
        let owner_id = batch.owner();
        let Some(owner) = self.owners.get_mut(&owner_id) else {
            let mut retired_batch = RetiredOutputs::with_capacity(batch.len());
            for completion in batch.into_completions() {
                let drop = PacketDrop::from_completion(
                    &completion,
                    PacketDropReason::UnknownOwner,
                    None,
                );
                drops.push(drop.clone());
                retired_batch.push_drop(drop);
            }
            if !retired_batch.is_empty() {
                retired.push(retired_batch);
            }
            return;
        };
        let retired_start = retired.len();
        let before_in_flight = owner.in_flight;
        owner.retire_batch_outputs_into(batch, retired, compact_endpoint_data);
        if owner.in_flight < before_in_flight {
            self.admission.wake_owner(owner_id);
            self.outbound_admission.wake_owner(owner_id);
        }
        for batch in &retired[retired_start..] {
            batch.append_drops_to(drops);
        }
    }

    fn admission_queue_lens(&self) -> (usize, usize) {
        self.admission.lens()
    }

    fn admission_ready_lens(&self) -> (usize, usize) {
        self.admission.ready_lens()
    }

    fn outbound_admission_queue_lens(&self) -> (usize, usize) {
        self.outbound_admission.lens()
    }

    fn outbound_admission_ready_lens(&self) -> (usize, usize) {
        self.outbound_admission.ready_lens()
    }

    fn record_authenticated_fsp_session(
        &mut self,
        session: DataplaneAuthenticatedFspSession,
    ) -> Option<bool> {
        self.owner_mut(session.owner)
            .and_then(|owner| owner.record_authenticated_fsp_session(session))
    }

    fn record_fsp_decrypt_failure(&mut self, owner: OwnerId) -> Option<u32> {
        self.owner_mut(owner)
            .and_then(OwnerState::record_fsp_decrypt_failure)
    }

}
