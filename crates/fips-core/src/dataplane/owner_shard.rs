/// Bound one owner's dispatch share while another owner in the same shard is
/// runnable. Eight packets is the dataplane's existing AEAD fairness quantum;
/// a lone owner still receives the caller's complete run limit.
const DATAPLANE_OUTBOUND_OWNER_FAIRNESS_PACKETS: usize = 8;

#[derive(Debug)]
struct DataplaneOwnerShard {
    index: usize,
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    admission_run: Vec<QueuedPacket>,
    outbound_admission_run: Vec<QueuedOutboundPacket>,
    owners: HashMap<OwnerId, OwnerState>,
    retire_owners: VecDeque<OwnerId>,
}

impl DataplaneOwnerShard {
    fn new(index: usize) -> Self {
        Self {
            index,
            admission: AdmissionQueue::new(),
            outbound_admission: OutboundAdmissionQueue::new(),
            admission_run: Vec::new(),
            outbound_admission_run: Vec::new(),
            owners: HashMap::new(),
            retire_owners: VecDeque::new(),
        }
    }

    fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) -> Vec<OwnerRetireSlot> {
        self.retire_owners.retain(|queued| *queued != owner);
        let orphaned = self
            .owners
            .insert(owner, OwnerState::new(owner, config))
            .map_or_else(Vec::new, |mut previous| {
                previous.take_pending_retirements()
            });
        self.admission.wake_owner(owner);
        self.outbound_admission.wake_owner(owner);
        orphaned
    }

    fn unregister_owner(&mut self, owner: OwnerId) -> Option<Vec<OwnerRetireSlot>> {
        self.retire_owners.retain(|queued| *queued != owner);
        let orphaned = self.owners.remove(&owner).map(|mut owner| {
            owner.take_pending_retirements()
        });
        if orphaned.is_some() {
            self.admission.wake_owner(owner);
            self.outbound_admission.wake_owner(owner);
        }
        orphaned
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
        prepared: &mut Vec<PreparedCryptoRun>,
        ready_slots: &mut Vec<Arc<CryptoReadySlot>>,
        priority_only: bool,
        fsp_path_open: &mut FspPathOpenDispatch,
        drops: &mut Vec<PacketDrop>,
    ) -> usize {
        let mut dispatched = 0usize;
        let mut attempts_remaining = self.admission.len();
        let mut prepared_run: Option<PreparedCryptoRun> = None;
        let mut prepared_epoch = None;
        while dispatched < limit && attempts_remaining > 0 {
            let run_limit = limit.saturating_sub(dispatched);
            let Some(cursor) = self.admission.pop_next_run_into(
                priority_only,
                run_limit,
                &mut self.admission_run,
            ) else {
                if !priority_only && limit > 0 {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::DataplaneDispatchNoIngress,
                    );
                }
                break;
            };
            attempts_remaining = attempts_remaining.saturating_sub(self.admission_run.len());
            if self.admission_run.len() > 1 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::DataplaneIngressOwnerRunContinue,
                    self.admission_run.len().saturating_sub(1) as u64,
                );
            }
            let owner_id = cursor.owner;

            let Some(owner) = self.owners.get_mut(&owner_id) else {
                for queued in &self.admission_run {
                    drops.push(PacketDrop::from_queued(
                        queued,
                        PacketDropReason::UnknownOwner,
                    ));
                }
                self.admission_run.clear();
                self.admission.continue_owner_lane(cursor);
                continue;
            };

            self.admission_run.reverse();
            while let Some(queued) = self.admission_run.pop() {
                if !owner.can_reserve_class(queued.packet.class) {
                    record_ingress_owner_blocked(owner.reserve_block_reason(queued.packet.class));
                    self.admission_run.push(queued);
                    self.admission_run.reverse();
                    break;
                }

                match owner.reserve(&queued.packet, queued.ingress_seq) {
                    Ok((reservation, receive_epoch)) => {
                        let packet_owner = queued.packet.owner;
                        let packet_counter = queued.packet.counter;
                        let packet_lane = queued.packet.lane();
                        let reservation = reservation.with_owner_shard(self.index);
                        fsp_path_open.count(&reservation);
                        let work = CryptoWork {
                            reservation,
                            packet: queued.packet,
                        };
                        let work = match prepared_run.as_mut() {
                            Some(run) if prepared_epoch == Some(receive_epoch) => {
                                run.try_push_open(work).err()
                            }
                            Some(_) => Some(work),
                            None => Some(work),
                        };
                        if let Some(work) = work {
                            if let Some(run) = prepared_run.take() {
                                prepared.push(run);
                            }
                            prepared_epoch = None;
                            match owner.open_key(receive_epoch) {
                                Some(open_key) => {
                                    prepared_run = Some(PreparedCryptoRun::open(work, open_key));
                                    prepared_epoch = Some(receive_epoch);
                                }
                                None => ready_slots.push(CryptoReadySlot::completed(
                                    failed_crypto_completion(
                                        work.reservation,
                                        CryptoFailureKind::Open,
                                    ),
                                )),
                            }
                        }
                        tracing::debug!(
                            owner = ?packet_owner,
                            counter = packet_counter,
                            lane = ?packet_lane,
                            "dataplane inbound dispatched"
                        );
                        dispatched = dispatched.saturating_add(1);
                        attempts_remaining = self.admission.len();
                    }
                    Err(error) => {
                        tracing::debug!(
                            owner = ?queued.packet.owner,
                            counter = queued.packet.counter,
                            generation = queued.packet.generation,
                            class = ?queued.packet.class,
                            lane = ?queued.packet.lane(),
                            wire_flags = queued.packet.wire_flags,
                            receive_epoch = ?queued.packet.receive_epoch,
                            ingress_seq = queued.ingress_seq,
                            reason = ?error,
                            "dataplane inbound reservation failed"
                        );
                        drops.push(PacketDrop::from_queued(&queued, error.into()));
                    }
                }
            }
            if self.admission_run.is_empty() {
                self.admission.continue_owner_lane(cursor);
            } else {
                self.admission
                    .defer_owner_run(cursor, &mut self.admission_run);
            }
        }
        if let Some(run) = prepared_run {
            prepared.push(run);
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
        prepared: &mut Vec<PreparedCryptoRun>,
        ready_slots: &mut Vec<Arc<CryptoReadySlot>>,
        priority_only: bool,
        drops: &mut Vec<PacketDrop>,
    ) -> usize {
        let mut dispatched = 0usize;
        let mut attempts_remaining = self.outbound_admission.len();
        let mut prepared_run: Option<PreparedCryptoRun> = None;
        while dispatched < limit && attempts_remaining > 0 {
            let remaining = limit.saturating_sub(dispatched);
            let ready_lens = self.outbound_admission.ready_lens();
            let ready_owners = if priority_only {
                ready_lens.0
            } else {
                ready_lens.0.saturating_add(ready_lens.1)
            };
            let run_limit = if ready_owners > 1 {
                remaining.min(DATAPLANE_OUTBOUND_OWNER_FAIRNESS_PACKETS)
            } else {
                remaining
            };
            let Some(cursor) = self.outbound_admission.pop_next_run_into(
                priority_only,
                run_limit,
                &mut self.outbound_admission_run,
            )
            else {
                break;
            };
            attempts_remaining =
                attempts_remaining.saturating_sub(self.outbound_admission_run.len());
            if self.outbound_admission_run.len() > 1 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::DataplaneOutboundOwnerRunContinue,
                    self.outbound_admission_run.len().saturating_sub(1) as u64,
                );
            }
            let owner_id = cursor.owner;

            let Some(owner) = self.owners.get_mut(&owner_id) else {
                for queued in &self.outbound_admission_run {
                    drops.push(PacketDrop::from_queued_outbound(
                        queued,
                        PacketDropReason::UnknownOwner,
                    ));
                }
                self.outbound_admission_run.clear();
                self.outbound_admission.continue_owner_lane(cursor);
                continue;
            };

            self.outbound_admission_run.reverse();
            while let Some(queued) = self.outbound_admission_run.pop() {
                let class = queued.packet.class;
                let ingress_seq = queued.ingress_seq;
                if !owner.can_reserve_class(class) {
                    record_outbound_owner_blocked(owner.reserve_block_reason(class));
                    self.outbound_admission_run.push(queued);
                    self.outbound_admission_run.reverse();
                    break;
                }

                let send_token = queued.packet.send_token;
                match owner.reserve_outbound(queued.packet, ingress_seq) {
                    Ok((reservation, packet)) => {
                        let reservation = reservation.with_owner_shard(self.index);
                        let work = OutboundCryptoWork {
                            reservation,
                            packet,
                        };
                        let work = match prepared_run.as_mut() {
                            Some(run) => run.try_push_seal(work).err(),
                            None => Some(work),
                        };
                        if let Some(work) = work {
                            if let Some(run) = prepared_run.take() {
                                prepared.push(run);
                            }
                            match owner.seal_key() {
                                Some(seal_key) => {
                                    prepared_run = Some(PreparedCryptoRun::seal(work, seal_key));
                                }
                                None => ready_slots.push(CryptoReadySlot::completed(
                                    failed_crypto_completion(
                                        work.reservation,
                                        CryptoFailureKind::Seal,
                                    ),
                                )),
                            }
                        }
                        dispatched = dispatched.saturating_add(1);
                    }
                    Err(error) => {
                        drops.push(PacketDrop {
                            owner: owner_id,
                            counter: None,
                            send_token,
                            reason: error.into(),
                            crypto_failure: None,
                            wire_flags: None,
                            authenticated_counter_highest: None,
                        });
                    }
                }
                attempts_remaining = self.outbound_admission.len();
            }
            if self.outbound_admission_run.is_empty() {
                self.outbound_admission.continue_owner_lane(cursor);
            } else {
                self.outbound_admission
                    .defer_owner_run(cursor, &mut self.outbound_admission_run);
            }
        }
        if let Some(run) = prepared_run {
            prepared.push(run);
        }
        dispatched
    }

    fn stage_retire_slot(
        &mut self,
        slot: Arc<CryptoReadySlot>,
    ) -> Result<(), Arc<CryptoReadySlot>> {
        let owner_id = slot.owner();
        let Some(owner) = self.owners.get_mut(&owner_id) else {
            return Err(slot);
        };
        if owner.stage_retire_slot(slot) {
            self.retire_owners.push_back(owner_id);
        }
        Ok(())
    }

    fn has_pending_retirements(&self) -> bool {
        !self.retire_owners.is_empty()
    }

    fn has_ready_retirements(&self) -> bool {
        self.retire_owners.iter().any(|owner| {
            self.owners
                .get(owner)
                .is_some_and(OwnerState::has_ready_retirement)
        })
    }

    fn retire_ready_slots_into(
        &mut self,
        limit: usize,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) -> usize {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneRetire);
        let owners_to_scan = self.retire_owners.len();
        let mut retired_count = 0usize;
        for remaining_owners in (1..=owners_to_scan).rev() {
            if retired_count >= limit {
                break;
            }
            let Some(owner_id) = self.retire_owners.pop_front() else {
                break;
            };
            let Some(owner) = self.owners.get_mut(&owner_id) else {
                continue;
            };
            let owner_limit = limit
                .saturating_sub(retired_count)
                .div_ceil(remaining_owners);
            let before_in_flight = owner.in_flight;
            let got = owner.retire_ready_slots_into(
                owner_limit,
                retired,
                drops,
                compact_endpoint_data,
            );
            retired_count = retired_count.saturating_add(got);
            if owner.in_flight < before_in_flight {
                self.admission.wake_owner(owner_id);
                self.outbound_admission.wake_owner(owner_id);
            }
            if owner.has_pending_retirements() {
                self.retire_owners.push_back(owner_id);
            }
        }
        retired_count
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
