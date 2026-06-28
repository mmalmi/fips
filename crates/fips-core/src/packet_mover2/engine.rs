#[derive(Debug)]
pub(crate) struct PacketMover2 {
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
    drops: Vec<PacketDrop>,
}

impl PacketMover2 {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            admission: AdmissionQueue::new(config),
            outbound_admission: OutboundAdmissionQueue::new(config),
            owners: HashMap::new(),
            drops: Vec::new(),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.owners.insert(owner, OwnerState::new(owner, config));
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> bool {
        self.owners.remove(&owner).is_some()
    }

    pub(crate) fn has_owner(&self, owner: OwnerId) -> bool {
        self.owners.contains_key(&owner)
    }

    pub(crate) fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.owners
            .get(&owner)
            .and_then(OwnerState::active_path)
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owners.get_mut(&owner)
    }

    fn owner_crypto_keys(&self, owner: OwnerId) -> Option<OwnerCryptoKeys> {
        self.owners.get(&owner).and_then(OwnerState::crypto_keys)
    }

    pub(crate) fn submit_socket_packet(
        &mut self,
        packet: SocketPacket,
    ) -> Result<u64, AdmissionDrop> {
        match self.admission.admit(packet) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
    }

    pub(crate) fn submit_socket_batch<I>(&mut self, packets: I) -> AdmissionBatchSummary
    where
        I: IntoIterator<Item = SocketPacket>,
    {
        let mut summary = AdmissionBatchSummary::default();
        for packet in packets {
            match self.submit_socket_packet(packet) {
                Ok(_) => summary.admitted += 1,
                Err(_) => summary.dropped += 1,
            }
        }
        summary
    }

    pub(crate) fn submit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
    ) -> Result<u64, OutboundAdmissionDrop> {
        match self.outbound_admission.admit(packet) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
    }

    pub(crate) fn dispatch_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> usize {
        work.clear();

        while work.len() < limit {
            let Some(queued) = self.admission.pop_next() else {
                break;
            };

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                continue;
            };
            if !owner.can_reserve_lane(queued.packet.lane()) {
                self.admission.push_front(queued);
                break;
            }

            match owner.reserve(&queued.packet, queued.ingress_seq) {
                Ok(reservation) => work.push(CryptoWork {
                    reservation,
                    packet: queued.packet,
                }),
                Err(error) => self
                    .drops
                    .push(PacketDrop::from_queued(&queued, error.into())),
            }
        }

        work.len()
    }

    pub(crate) fn dispatch_outbound_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> usize {
        work.clear();

        while work.len() < limit {
            let Some(queued) = self.outbound_admission.pop_next() else {
                break;
            };

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued_outbound(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                continue;
            };

            let owner_id = queued.packet.owner;
            let lane = queued.packet.lane();
            let ingress_seq = queued.ingress_seq;
            if !owner.can_reserve_lane(lane) {
                self.outbound_admission.push_front(queued);
                break;
            }
            match owner.reserve_outbound(queued.packet, ingress_seq) {
                Ok((reservation, packet)) => work.push(OutboundCryptoWork {
                    reservation,
                    packet,
                }),
                Err(error) => self.drops.push(PacketDrop {
                    owner: owner_id,
                    counter: None,
                    ingress_seq: Some(ingress_seq),
                    lane,
                    reason: error.into(),
                    crypto_failure: None,
                    wire_flags: None,
                    authenticated_counter_highest: None,
                }),
            }
        }

        work.len()
    }

    fn dispatch_outbound_priority_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> usize {
        work.clear();

        while work.len() < limit {
            let Some(queued) = self.outbound_admission.pop_next_priority() else {
                break;
            };

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued_outbound(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                continue;
            };

            let owner_id = queued.packet.owner;
            let lane = queued.packet.lane();
            let ingress_seq = queued.ingress_seq;
            if !owner.can_reserve_lane(lane) {
                self.outbound_admission.push_front(queued);
                break;
            }
            match owner.reserve_outbound(queued.packet, ingress_seq) {
                Ok((reservation, packet)) => work.push(OutboundCryptoWork {
                    reservation,
                    packet,
                }),
                Err(error) => self.drops.push(PacketDrop {
                    owner: owner_id,
                    counter: None,
                    ingress_seq: Some(ingress_seq),
                    lane,
                    reason: error.into(),
                    crypto_failure: None,
                    wire_flags: None,
                    authenticated_counter_highest: None,
                }),
            }
        }

        work.len()
    }

    pub(crate) fn retire_completion(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2Retire);
        let Some(owner) = self.owners.get_mut(&completion.reservation.owner) else {
            return vec![RetiredPacket::Drop(PacketDrop::from_completion(
                &completion,
                PacketDropReason::UnknownOwner,
                None,
            ))];
        };
        let retired = owner.retire(completion);
        self.drops
            .extend(retired.iter().filter_map(|item| match item {
                RetiredPacket::Drop(drop) => Some(drop.clone()),
                RetiredPacket::Output(_) => None,
                RetiredPacket::Outbound(_) => None,
            }));
        retired
    }

    #[cfg(test)]
    pub(crate) fn execute_work(&self, work: CryptoWork) -> CryptoCompletion {
        copy_crypto_completion(work)
    }

    #[cfg(test)]
    pub(crate) fn dispatch_available(&mut self, limit: usize) -> Vec<CryptoWork> {
        let mut work = Vec::new();
        self.dispatch_available_into(limit, &mut work);
        work
    }

    #[cfg(test)]
    pub(crate) fn dispatch_outbound_available(&mut self, limit: usize) -> Vec<OutboundCryptoWork> {
        let mut work = Vec::new();
        self.dispatch_outbound_available_into(limit, &mut work);
        work
    }

    #[cfg(test)]
    pub(crate) fn run_available(&mut self, limit: usize) -> PacketMoverTurn {
        let mut work = Vec::new();
        self.run_available_with_work_buffer(limit, &mut work)
    }

    #[cfg(test)]
    pub(crate) fn run_available_with_work_buffer(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> PacketMoverTurn {
        let dispatched = self.dispatch_available_into(limit, work);
        let mut retired = Vec::new();
        for work in work.drain(..) {
            let completion = copy_crypto_completion(work);
            retired.extend(self.retire_completion(completion));
        }
        PacketMoverTurn {
            dispatched,
            retired,
            drops: self.drain_drops(),
        }
    }

    #[cfg(test)]
    pub(crate) fn run_aead_available(&mut self, limit: usize) -> PacketMoverTurn {
        let mut open_work = Vec::new();
        let mut seal_work = Vec::new();
        self.run_aead_available_with_work_buffers(limit, &mut open_work, &mut seal_work)
    }

    #[cfg(test)]
    pub(crate) fn run_aead_available_with_work_buffers(
        &mut self,
        limit: usize,
        open_work: &mut Vec<CryptoWork>,
        seal_work: &mut Vec<OutboundCryptoWork>,
    ) -> PacketMoverTurn {
        let mut retired = Vec::new();
        let mut drops = Vec::new();
        let dispatched =
            self.run_aead_available_into(limit, open_work, seal_work, &mut retired, &mut drops);

        PacketMoverTurn {
            dispatched,
            retired,
            drops,
        }
    }

    pub(crate) fn run_aead_available_into(
        &mut self,
        limit: usize,
        open_work: &mut Vec<CryptoWork>,
        seal_work: &mut Vec<OutboundCryptoWork>,
        retired: &mut Vec<RetiredPacket>,
        drops: &mut Vec<PacketDrop>,
    ) -> usize {
        retired.clear();
        open_work.clear();
        seal_work.clear();
        let mut aead_jobs = Vec::new();
        let mut completions = Vec::new();
        let outbound_priority_reserve =
            outbound_priority_dispatch_limit(limit, self.outbound_admission.has_priority_pending());
        let pre_priority_inbound_limit =
            inbound_before_outbound_priority_limit(limit, outbound_priority_reserve);
        let mut fsp_worker_open = 0u64;
        let mut fsp_worker_open_bulk = 0u64;
        let pre_priority_inbound_dispatched =
            self.dispatch_available_into(pre_priority_inbound_limit, open_work);
        self.execute_open_work_batch(
            open_work,
            &mut aead_jobs,
            &mut completions,
            retired,
            &mut fsp_worker_open,
            &mut fsp_worker_open_bulk,
        );

        let priority_outbound_dispatched =
            self.dispatch_outbound_priority_available_into(outbound_priority_reserve, seal_work);
        self.execute_seal_work_batch(seal_work.drain(..), &mut aead_jobs, &mut completions, retired);

        let dispatched_before_bulk =
            pre_priority_inbound_dispatched.saturating_add(priority_outbound_dispatched);
        let inbound_dispatched =
            self.dispatch_available_into(limit.saturating_sub(dispatched_before_bulk), open_work);
        let outbound_dispatched = self.dispatch_outbound_available_into(
            limit.saturating_sub(dispatched_before_bulk + inbound_dispatched),
            seal_work,
        );

        let leading_priority_seals = seal_work
            .iter()
            .take_while(|work| work.reservation.lane == Lane::Priority)
            .count();
        self.execute_seal_work_batch(
            seal_work.drain(..leading_priority_seals),
            &mut aead_jobs,
            &mut completions,
            retired,
        );

        self.execute_open_work_batch(
            open_work,
            &mut aead_jobs,
            &mut completions,
            retired,
            &mut fsp_worker_open,
            &mut fsp_worker_open_bulk,
        );
        record_fsp_worker_open_dispatch(fsp_worker_open, fsp_worker_open_bulk);

        self.execute_seal_work_batch(seal_work.drain(..), &mut aead_jobs, &mut completions, retired);

        drops.extend(self.drain_drops());
        pre_priority_inbound_dispatched
            + priority_outbound_dispatched
            + inbound_dispatched
            + outbound_dispatched
    }

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    fn execute_open_work_batch(
        &mut self,
        open_work: &mut Vec<CryptoWork>,
        aead_jobs: &mut Vec<PacketMover2AeadJob>,
        completions: &mut Vec<CryptoCompletion>,
        retired: &mut Vec<RetiredPacket>,
        fsp_worker_open: &mut u64,
        fsp_worker_open_bulk: &mut u64,
    ) {
        aead_jobs.clear();
        completions.clear();
        for work in open_work.drain(..) {
            let reservation = work.reservation.clone();
            count_fsp_worker_open_dispatch(&reservation, fsp_worker_open, fsp_worker_open_bulk);
            match self.owner_crypto_keys(reservation.owner) {
                Some(keys) => aead_jobs.push(PacketMover2AeadJob::Open {
                    work,
                    cipher: keys.open,
                }),
                None => completions.push(CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Open),
                }),
            }
        }
        packet_mover2_aead_pool().execute_jobs_into(aead_jobs, completions);
        for completion in completions.drain(..) {
            retired.extend(self.retire_completion(completion));
        }
    }

    fn execute_seal_work_batch<I>(
        &mut self,
        seal_work: I,
        aead_jobs: &mut Vec<PacketMover2AeadJob>,
        completions: &mut Vec<CryptoCompletion>,
        retired: &mut Vec<RetiredPacket>,
    ) where
        I: IntoIterator<Item = OutboundCryptoWork>,
    {
        aead_jobs.clear();
        completions.clear();
        for work in seal_work {
            let reservation = work.reservation.clone();
            match self.owner_crypto_keys(reservation.owner) {
                Some(keys) => aead_jobs.push(PacketMover2AeadJob::Seal {
                    work,
                    cipher: keys.seal,
                }),
                None => completions.push(CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Seal),
                }),
            }
        }
        packet_mover2_aead_pool().execute_jobs_into(aead_jobs, completions);
        for completion in completions.drain(..) {
            retired.extend(self.retire_completion(completion));
        }
    }

    #[cfg(test)]
    fn queue_lens(&self) -> (usize, usize) {
        self.admission.lens()
    }

    #[cfg(test)]
    fn outbound_queue_lens(&self) -> (usize, usize) {
        self.outbound_admission.lens()
    }
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

fn count_fsp_worker_open_dispatch(
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

fn record_fsp_worker_open_dispatch(total: u64, bulk: u64) {
    if total == 0 {
        return;
    }

    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspOwnerSame,
        total,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspPathWorkerOpen,
        total,
    );
    if bulk > 0 {
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DecryptFspPathWorkerOpenBulk,
            bulk,
        );
    }
}
