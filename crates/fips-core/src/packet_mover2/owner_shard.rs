#[derive(Debug)]
struct PacketMover2OwnerShard {
    index: usize,
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    completed: VecDeque<CryptoCompletion>,
    owners: HashMap<OwnerId, OwnerState>,
}

impl PacketMover2OwnerShard {
    fn new(index: usize) -> Self {
        Self {
            index,
            admission: AdmissionQueue::new(),
            outbound_admission: OutboundAdmissionQueue::new(),
            completed: VecDeque::new(),
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

    fn owner_fsp_activity(&self, owner: OwnerId) -> Option<PacketMover2FspOwnerActivity> {
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

    fn owner_fsp_mmp_snapshot(&self, owner: OwnerId) -> Option<PacketMover2FspMmpSnapshot> {
        self.owner(owner).and_then(OwnerState::fsp_mmp_snapshot)
    }

    fn owner_fsp_send_context(&self, owner: OwnerId) -> Option<PacketMover2FspSendContext> {
        self.owner(owner).and_then(OwnerState::fsp_send_context)
    }

    fn owner_fmp_send_context(&self, owner: OwnerId) -> Option<PacketMover2FmpSendContext> {
        self.owner(owner).and_then(OwnerState::fmp_send_context)
    }

    fn owner_fmp_link_metrics(
        &self,
        owner: OwnerId,
        now: std::time::Instant,
    ) -> Option<PacketMover2FmpLinkMetrics> {
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
        batch: &mut PacketMover2FmpMmpReportBatch,
    ) {
        for owner in self.owners.values_mut() {
            owner.collect_fmp_mmp_reports(now, batch);
        }
    }

    fn collect_fsp_mmp_reports(
        &mut self,
        now: std::time::Instant,
        batch: &mut PacketMover2FspMmpReportBatch,
    ) {
        for owner in self.owners.values_mut() {
            owner.collect_fsp_mmp_reports(now, batch);
        }
    }

    fn record_fsp_mmp_send_result(
        &mut self,
        owner: OwnerId,
        success: bool,
    ) -> Option<PacketMover2FspMmpReportingResumed> {
        self.owner_mut(owner)
            .and_then(|owner| owner.record_fsp_mmp_send_result(success))
    }

    fn seed_fsp_path_mtu(
        &mut self,
        owner: OwnerId,
        path_mtu: u16,
    ) -> Result<(), PacketMover2FspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(PacketMover2FspMmpSkip::UnknownOwner)?
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
    ) -> Result<PacketMover2FspReceiverReportResult, PacketMover2FspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(PacketMover2FspMmpSkip::UnknownOwner)?
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
    ) -> Result<PacketMover2FspPathMtuApplyResult, PacketMover2FspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(PacketMover2FspMmpSkip::UnknownOwner)?
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
            .filter(|activity| activity.tracks_next_hop(next_hop))
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
                        crate::perf_profile::Event::PacketMover2DispatchNoIngress,
                    );
                }
                break;
            };
            attempts_remaining = attempts_remaining.saturating_sub(run.items.len());
            if run.items.len() > 1 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::PacketMover2IngressOwnerRunContinue,
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
                    record_owner_blocked(owner.reserve_block_reason(queued.packet.class));
                    remaining.push(queued);
                    remaining.extend(items);
                    break;
                }

                match owner.reserve(&queued.packet, queued.ingress_seq) {
                    Ok(reservation) => {
                        let reservation = reservation.with_owner_shard(self.index);
                        count_fsp_path_open_dispatch(
                            &reservation,
                            fsp_path_open,
                            fsp_path_open_bulk,
                        );
                        let open_key = owner.open_key_for_packet(&queued.packet);
                        let work = CryptoWork {
                            reservation: reservation.clone(),
                            packet: queued.packet,
                        };
                        let prepared_work = match open_key {
                            Some(open_key) => PreparedCryptoWork::open(work, open_key),
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
                crate::perf_profile::Event::PacketMover2DispatchLimitHit,
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
                    crate::perf_profile::Event::PacketMover2OutboundOwnerRunContinue,
                    run.items.len().saturating_sub(1) as u64,
                );
            }
            let owner_id = run.cursor.owner;

            let Some(owner) = self.owners.get(&owner_id) else {
                for queued in &run.items {
                    drops.push(PacketDrop::from_queued_outbound(
                        queued,
                        PacketDropReason::UnknownOwner,
                    ));
                }
                self.outbound_admission.continue_owner_lane(run.cursor);
                continue;
            };
            let keys = owner.crypto_keys();

            let owner = self
                .owners
                .get_mut(&owner_id)
                .expect("outbound owner checked before reservation");
            let mut remaining = Vec::new();
            let mut items = std::mem::take(&mut run.items).into_iter();
            while let Some(queued) = items.next() {
                let lane = queued.packet.lane();
                let class = queued.packet.class;
                let ingress_seq = queued.ingress_seq;
                if !owner.can_reserve_class(class) {
                    record_owner_blocked(owner.reserve_block_reason(class));
                    remaining.push(queued);
                    remaining.extend(items);
                    break;
                }

                match owner.reserve_outbound(queued.packet, ingress_seq) {
                    Ok((reservation, packet)) => {
                        let reservation = reservation.with_owner_shard(self.index);
                        let work = OutboundCryptoWork::new(reservation.clone(), packet);
                        let prepared_work = match &keys {
                            Some(keys) => PreparedCryptoWork::seal(work, keys.seal.clone()),
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
                            ingress_seq: Some(ingress_seq),
                            lane,
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

    pub(crate) fn retire_completion_into(
        &mut self,
        completion: CryptoCompletion,
        retired: &mut Vec<RetiredPacket>,
        drops: &mut Vec<PacketDrop>,
    ) {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2Retire);
        let owner_id = completion.reservation.owner;
        let Some(owner) = self.owners.get_mut(&owner_id) else {
            let drop = PacketDrop::from_completion(
                &completion,
                PacketDropReason::UnknownOwner,
                None,
            );
            drops.push(drop.clone());
            retired.push(RetiredPacket::Drop(drop));
            return;
        };
        let retired_start = retired.len();
        let before_in_flight = owner.in_flight;
        owner.retire_into(completion, retired);
        if owner.in_flight < before_in_flight {
            self.admission.wake_owner(owner_id);
            self.outbound_admission.wake_owner(owner_id);
        }
        drops.extend(retired[retired_start..].iter().filter_map(|item| match item {
                RetiredPacket::Drop(drop) => Some(drop.clone()),
                RetiredPacket::Output(_) => None,
                RetiredPacket::Outbound(_) => None,
            }));
    }

    fn queue_completion(&mut self, completion: CryptoCompletion) -> bool {
        let was_empty = self.completed.is_empty();
        self.completed.push_back(completion);
        was_empty
    }

    fn retire_queued_completion_into(
        &mut self,
        retired: &mut Vec<RetiredPacket>,
        drops: &mut Vec<PacketDrop>,
    ) -> bool {
        let Some(completion) = self.completed.pop_front() else {
            return false;
        };
        self.retire_completion_into(completion, retired, drops);
        true
    }

    fn retire_queued_completions_into(
        &mut self,
        limit: usize,
        retired: &mut Vec<RetiredPacket>,
        drops: &mut Vec<PacketDrop>,
    ) -> usize {
        let mut retired_count = 0usize;
        while retired_count < limit && self.retire_queued_completion_into(retired, drops) {
            retired_count = retired_count.saturating_add(1);
        }
        retired_count
    }

    fn has_queued_completions(&self) -> bool {
        !self.completed.is_empty()
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
        owner: OwnerId,
        previous_hop: NodeAddr,
        msg_type: u8,
        body_len: usize,
        sync: FspReceiveSync,
        activity_tick: Option<ActivityTick>,
        now: std::time::Instant,
    ) -> Option<bool> {
        self.owner_mut(owner).and_then(|owner| {
            owner.record_authenticated_fsp_session(
                previous_hop,
                msg_type,
                body_len,
                sync,
                activity_tick,
                now,
            )
        })
    }

    fn record_fsp_decrypt_failure(&mut self, owner: OwnerId) -> Option<u32> {
        self.owner_mut(owner)
            .and_then(OwnerState::record_fsp_decrypt_failure)
    }

    fn record_fsp_data_sent(
        &mut self,
        owner: OwnerId,
        next_hop: NodeAddr,
        bytes: usize,
        tick: ActivityTick,
    ) -> bool {
        self.owner_mut(owner)
            .is_some_and(|owner| owner.record_fsp_data_sent(next_hop, bytes, tick))
    }
}
