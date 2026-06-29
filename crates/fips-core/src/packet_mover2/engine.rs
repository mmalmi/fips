#[derive(Debug)]
pub(crate) struct PacketMover2 {
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
    aead_workers: Option<AeadWorkerPool>,
    aead_worker_backlog: VecDeque<AeadWorkerJob>,
    aead_worker_in_flight: usize,
    aead_completion_notify: Arc<tokio::sync::Notify>,
    drops: Vec<PacketDrop>,
}

impl PacketMover2 {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            admission: AdmissionQueue::new(config),
            outbound_admission: OutboundAdmissionQueue::new(config),
            owners: HashMap::new(),
            aead_workers: None,
            aead_worker_backlog: VecDeque::new(),
            aead_worker_in_flight: 0,
            aead_completion_notify: Arc::new(tokio::sync::Notify::new()),
            drops: Vec::new(),
        }
    }

    pub(crate) fn new_with_aead_workers(config: AdmissionConfig) -> Self {
        let mut mover = Self::new(config);
        mover.spawn_aead_workers(default_aead_worker_count());
        mover
    }

    fn spawn_aead_workers(&mut self, workers: usize) {
        if workers == 0 || self.aead_workers.is_some() {
            return;
        }
        self.aead_workers = Some(AeadWorkerPool::spawn(
            workers,
            self.aead_completion_notify.clone(),
        ));
    }

    pub(crate) fn aead_completion_notify(&self) -> Arc<tokio::sync::Notify> {
        self.aead_completion_notify.clone()
    }

    pub(crate) fn pending_aead_work(&self) -> usize {
        let backlog = self.aead_worker_backlog.len();
        backlog.saturating_add(self.aead_worker_in_flight)
    }

    pub(crate) fn has_ready_aead_completions(&self) -> bool {
        matches!(&self.aead_workers, Some(workers) if workers.has_ready_completions())
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
        if self.aead_workers.is_some() {
            return self.run_worker_aead_available_into(
                limit, open_work, seal_work, retired, drops,
            );
        }
        retired.clear();
        open_work.clear();
        seal_work.clear();
        let opened = StatelessAeadOpenWorker;
        let sealed = StatelessAeadSealWorker;
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
            &opened,
            retired,
            &mut fsp_worker_open,
            &mut fsp_worker_open_bulk,
        );

        let priority_outbound_dispatched =
            self.dispatch_outbound_priority_available_into(outbound_priority_reserve, seal_work);
        for work in seal_work.drain(..) {
            let completion = self.execute_seal_work(work, &sealed);
            retired.extend(self.retire_completion(completion));
        }

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
        for work in seal_work.drain(..leading_priority_seals) {
            let completion = self.execute_seal_work(work, &sealed);
            retired.extend(self.retire_completion(completion));
        }

        self.execute_open_work_batch(
            open_work,
            &opened,
            retired,
            &mut fsp_worker_open,
            &mut fsp_worker_open_bulk,
        );
        record_fsp_worker_open_dispatch(fsp_worker_open, fsp_worker_open_bulk);

        for work in seal_work.drain(..) {
            let completion = self.execute_seal_work(work, &sealed);
            retired.extend(self.retire_completion(completion));
        }

        drops.extend(self.drain_drops());
        pre_priority_inbound_dispatched
            + priority_outbound_dispatched
            + inbound_dispatched
            + outbound_dispatched
    }

    fn run_worker_aead_available_into(
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

        self.drain_aead_worker_completions(retired);
        self.flush_aead_worker_backlog();
        if self.aead_worker_backlog.len() >= PACKET_MOVER2_AEAD_WORKER_BACKLOG_CAP {
            drops.extend(self.drain_drops());
            return 0;
        }

        let outbound_priority_reserve =
            outbound_priority_dispatch_limit(limit, self.outbound_admission.has_priority_pending());
        let pre_priority_inbound_limit =
            inbound_before_outbound_priority_limit(limit, outbound_priority_reserve);
        let mut fsp_worker_open = 0u64;
        let mut fsp_worker_open_bulk = 0u64;

        let pre_priority_inbound_dispatched =
            self.dispatch_available_into(pre_priority_inbound_limit, open_work);
        self.enqueue_open_work_batch(
            open_work,
            &mut fsp_worker_open,
            &mut fsp_worker_open_bulk,
            retired,
        );

        let priority_outbound_dispatched =
            self.dispatch_outbound_priority_available_into(outbound_priority_reserve, seal_work);
        self.enqueue_seal_work_batch(seal_work, retired);

        let dispatched_before_bulk =
            pre_priority_inbound_dispatched.saturating_add(priority_outbound_dispatched);
        let inbound_dispatched =
            self.dispatch_available_into(limit.saturating_sub(dispatched_before_bulk), open_work);
        let outbound_dispatched = self.dispatch_outbound_available_into(
            limit.saturating_sub(dispatched_before_bulk + inbound_dispatched),
            seal_work,
        );

        self.enqueue_open_work_batch(
            open_work,
            &mut fsp_worker_open,
            &mut fsp_worker_open_bulk,
            retired,
        );
        record_fsp_worker_open_dispatch(fsp_worker_open, fsp_worker_open_bulk);
        self.enqueue_seal_work_batch(seal_work, retired);

        self.drain_aead_worker_completions(retired);
        drops.extend(self.drain_drops());

        pre_priority_inbound_dispatched
            + priority_outbound_dispatched
            + inbound_dispatched
            + outbound_dispatched
    }

    fn enqueue_open_work_batch(
        &mut self,
        open_work: &mut Vec<CryptoWork>,
        fsp_worker_open: &mut u64,
        fsp_worker_open_bulk: &mut u64,
        retired: &mut Vec<RetiredPacket>,
    ) {
        for work in open_work.drain(..) {
            count_fsp_worker_open_dispatch(&work.reservation, fsp_worker_open, fsp_worker_open_bulk);
            match self.prepare_open_worker_job(work) {
                Ok(job) => {
                    if let Some(completion) = self.submit_aead_worker_job(job) {
                        retired.extend(self.retire_completion(completion));
                    }
                }
                Err(completion) => retired.extend(self.retire_completion(completion)),
            }
        }
    }

    fn enqueue_seal_work_batch(
        &mut self,
        seal_work: &mut Vec<OutboundCryptoWork>,
        retired: &mut Vec<RetiredPacket>,
    ) {
        let leading_priority_seals = seal_work
            .iter()
            .take_while(|work| work.reservation.lane == Lane::Priority)
            .count();
        for work in seal_work.drain(..leading_priority_seals) {
            match self.prepare_seal_worker_job(work) {
                Ok(job) => {
                    if let Some(completion) = self.submit_aead_worker_job(job) {
                        retired.extend(self.retire_completion(completion));
                    }
                }
                Err(completion) => retired.extend(self.retire_completion(completion)),
            }
        }
        for work in seal_work.drain(..) {
            match self.prepare_seal_worker_job(work) {
                Ok(job) => {
                    if let Some(completion) = self.submit_aead_worker_job(job) {
                        retired.extend(self.retire_completion(completion));
                    }
                }
                Err(completion) => retired.extend(self.retire_completion(completion)),
            }
        }
    }

    fn prepare_open_worker_job(&self, work: CryptoWork) -> Result<AeadWorkerJob, CryptoCompletion> {
        let reservation = work.reservation.clone();
        match self.owner_crypto_keys(reservation.owner) {
            Some(keys) => match AeadOpenWork::from_crypto_work(work, keys.open) {
                Ok(work) => Ok(AeadWorkerJob::Open(work)),
                Err(_) => Err(CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Open),
                }),
            },
            None => Err(CryptoCompletion {
                reservation,
                result: CryptoResult::Failed(CryptoFailureKind::Open),
            }),
        }
    }

    fn prepare_seal_worker_job(
        &self,
        work: OutboundCryptoWork,
    ) -> Result<AeadWorkerJob, CryptoCompletion> {
        let reservation = work.reservation.clone();
        match self.owner_crypto_keys(reservation.owner) {
            Some(keys) => match AeadSealWork::from_outbound_work(work, keys.seal) {
                Ok(work) => Ok(AeadWorkerJob::Seal(work)),
                Err(_) => Err(CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Seal),
                }),
            },
            None => Err(CryptoCompletion {
                reservation,
                result: CryptoResult::Failed(CryptoFailureKind::Seal),
            }),
        }
    }

    fn submit_aead_worker_job(&mut self, job: AeadWorkerJob) -> Option<CryptoCompletion> {
        let Some(workers) = self.aead_workers.as_ref() else {
            return Some(job.failed_completion());
        };
        match workers.submit(job) {
            Ok(()) => {
                self.aead_worker_in_flight = self.aead_worker_in_flight.saturating_add(1);
                None
            }
            Err(job) => {
                if self.aead_worker_backlog.len() < PACKET_MOVER2_AEAD_WORKER_BACKLOG_CAP {
                    self.aead_worker_backlog.push_back(job);
                    None
                } else {
                    Some(job.failed_completion())
                }
            }
        }
    }

    fn flush_aead_worker_backlog(&mut self) {
        let Some(workers) = self.aead_workers.as_ref() else {
            return;
        };
        while let Some(job) = self.aead_worker_backlog.pop_front() {
            match workers.submit(job) {
                Ok(()) => {
                    self.aead_worker_in_flight = self.aead_worker_in_flight.saturating_add(1);
                }
                Err(job) => {
                    self.aead_worker_backlog.push_front(job);
                    break;
                }
            }
        }
    }

    fn drain_aead_worker_completions(&mut self, retired: &mut Vec<RetiredPacket>) -> usize {
        let completions: Vec<_> = match self.aead_workers.as_ref() {
            Some(workers) => std::iter::from_fn(|| workers.try_recv_completion()).collect(),
            None => return 0,
        };
        let drained = completions.len();
        for completion in completions {
            self.aead_worker_in_flight = self.aead_worker_in_flight.saturating_sub(1);
            retired.extend(self.retire_completion(completion));
        }
        drained
    }

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    fn execute_seal_work(
        &mut self,
        work: OutboundCryptoWork,
        sealed: &StatelessAeadSealWorker,
    ) -> CryptoCompletion {
        let reservation = work.reservation.clone();
        match self.owner_crypto_keys(reservation.owner) {
            Some(keys) => {
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadSeal,
                );
                match AeadSealWork::from_outbound_work(work, keys.seal) {
                    Ok(work) => sealed.execute(work),
                    Err(_) => CryptoCompletion {
                        reservation,
                        result: CryptoResult::Failed(CryptoFailureKind::Seal),
                    },
                }
            }
            None => CryptoCompletion {
                reservation,
                result: CryptoResult::Failed(CryptoFailureKind::Seal),
            },
        }
    }

    fn execute_open_work_batch(
        &mut self,
        open_work: &mut Vec<CryptoWork>,
        opened: &StatelessAeadOpenWorker,
        retired: &mut Vec<RetiredPacket>,
        fsp_worker_open: &mut u64,
        fsp_worker_open_bulk: &mut u64,
    ) {
        for work in open_work.drain(..) {
            let reservation = work.reservation.clone();
            count_fsp_worker_open_dispatch(&reservation, fsp_worker_open, fsp_worker_open_bulk);
            let completion = match self.owner_crypto_keys(reservation.owner) {
                Some(keys) => {
                    let _timer = crate::perf_profile::Timer::start(
                        crate::perf_profile::Stage::PacketMover2AeadOpen,
                    );
                    match AeadOpenWork::from_crypto_work(work, keys.open) {
                        Ok(work) => opened.execute(work),
                        Err(_) => CryptoCompletion {
                            reservation,
                            result: CryptoResult::Failed(CryptoFailureKind::Open),
                        },
                    }
                }
                None => CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Open),
                },
            };
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

const PACKET_MOVER2_AEAD_WORKER_PRIORITY_CAP: usize = 1024;
const PACKET_MOVER2_AEAD_WORKER_BULK_CAP: usize = 4096;
const PACKET_MOVER2_AEAD_WORKER_BACKLOG_CAP: usize = 5120;

enum AeadWorkerJob {
    Open(AeadOpenWork),
    Seal(AeadSealWork),
}

impl std::fmt::Debug for AeadWorkerJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(_) => f.write_str("AeadWorkerJob::Open"),
            Self::Seal(_) => f.write_str("AeadWorkerJob::Seal"),
        }
    }
}

impl AeadWorkerJob {
    fn lane(&self) -> Lane {
        match self {
            Self::Open(work) => work.work.reservation.lane,
            Self::Seal(work) => work.work.reservation.lane,
        }
    }

    fn failed_completion(self) -> CryptoCompletion {
        match self {
            Self::Open(work) => CryptoCompletion {
                reservation: work.work.reservation,
                result: CryptoResult::Failed(CryptoFailureKind::Open),
            },
            Self::Seal(work) => CryptoCompletion {
                reservation: work.work.reservation,
                result: CryptoResult::Failed(CryptoFailureKind::Seal),
            },
        }
    }

    fn execute(
        self,
        opened: &StatelessAeadOpenWorker,
        sealed: &StatelessAeadSealWorker,
    ) -> CryptoCompletion {
        match self {
            Self::Open(work) => {
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadOpen,
                );
                opened.execute(work)
            }
            Self::Seal(work) => {
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadSeal,
                );
                sealed.execute(work)
            }
        }
    }
}

struct AeadWorkerPool {
    priority_tx: Option<crossbeam_channel::Sender<AeadWorkerJob>>,
    bulk_tx: Option<crossbeam_channel::Sender<AeadWorkerJob>>,
    shutdown_tx: Option<crossbeam_channel::Sender<()>>,
    completion_rx: crossbeam_channel::Receiver<CryptoCompletion>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for AeadWorkerPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AeadWorkerPool")
    }
}

impl AeadWorkerPool {
    fn spawn(workers: usize, completion_notify: Arc<tokio::sync::Notify>) -> Self {
        let (priority_tx, priority_rx) =
            crossbeam_channel::bounded(PACKET_MOVER2_AEAD_WORKER_PRIORITY_CAP);
        let (bulk_tx, bulk_rx) = crossbeam_channel::bounded(PACKET_MOVER2_AEAD_WORKER_BULK_CAP);
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(workers);
        let (completion_tx, completion_rx) = crossbeam_channel::unbounded();
        let mut handles = Vec::with_capacity(workers);

        for worker_idx in 0..workers {
            let priority_rx = priority_rx.clone();
            let bulk_rx = bulk_rx.clone();
            let shutdown_rx = shutdown_rx.clone();
            let completion_tx = completion_tx.clone();
            let completion_notify = completion_notify.clone();
            let handle = std::thread::Builder::new()
                .name(format!("pm2-aead-{worker_idx}"))
                .spawn(move || {
                    run_aead_worker(
                        priority_rx,
                        bulk_rx,
                        shutdown_rx,
                        completion_tx,
                        completion_notify,
                    );
                })
                .expect("spawn packet_mover2 AEAD worker");
            handles.push(handle);
        }
        drop(completion_tx);

        Self {
            priority_tx: Some(priority_tx),
            bulk_tx: Some(bulk_tx),
            shutdown_tx: Some(shutdown_tx),
            completion_rx,
            handles,
        }
    }

    fn submit(&self, job: AeadWorkerJob) -> Result<(), AeadWorkerJob> {
        let tx = match job.lane() {
            Lane::Priority => self.priority_tx.as_ref(),
            Lane::Bulk => self.bulk_tx.as_ref(),
        };
        match tx {
            Some(tx) => tx.try_send(job).map_err(|error| match error {
                crossbeam_channel::TrySendError::Full(job)
                | crossbeam_channel::TrySendError::Disconnected(job) => job,
            }),
            None => Err(job),
        }
    }

    fn try_recv_completion(&self) -> Option<CryptoCompletion> {
        self.completion_rx.try_recv().ok()
    }

    fn has_ready_completions(&self) -> bool {
        !self.completion_rx.is_empty()
    }
}

impl Drop for AeadWorkerPool {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.as_ref() {
            for _ in 0..self.handles.len() {
                let _ = shutdown_tx.send(());
            }
        }
        self.priority_tx.take();
        self.bulk_tx.take();
        self.shutdown_tx.take();
        while let Some(handle) = self.handles.pop() {
            let _ = handle.join();
        }
    }
}

fn run_aead_worker(
    priority_rx: crossbeam_channel::Receiver<AeadWorkerJob>,
    bulk_rx: crossbeam_channel::Receiver<AeadWorkerJob>,
    shutdown_rx: crossbeam_channel::Receiver<()>,
    completion_tx: crossbeam_channel::Sender<CryptoCompletion>,
    completion_notify: Arc<tokio::sync::Notify>,
) {
    let opened = StatelessAeadOpenWorker;
    let sealed = StatelessAeadSealWorker;
    let never_rx = crossbeam_channel::never();
    let mut priority_open = true;
    let mut bulk_open = true;

    while priority_open || bulk_open {
        if priority_open {
            match priority_rx.try_recv() {
                Ok(job) => {
                    if !finish_aead_worker_job(
                        job,
                        &opened,
                        &sealed,
                        &completion_tx,
                        &completion_notify,
                    ) {
                        break;
                    }
                    continue;
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {}
                Err(crossbeam_channel::TryRecvError::Disconnected) => priority_open = false,
            }
        }

        let priority_recv = if priority_open {
            &priority_rx
        } else {
            &never_rx
        };
        let bulk_recv = if bulk_open { &bulk_rx } else { &never_rx };
        crossbeam_channel::select! {
            recv(priority_recv) -> msg => match msg {
                Ok(job) => {
                    if !finish_aead_worker_job(
                        job,
                        &opened,
                        &sealed,
                        &completion_tx,
                        &completion_notify,
                    ) {
                        break;
                    }
                }
                Err(_) => priority_open = false,
            },
            recv(bulk_recv) -> msg => match msg {
                Ok(job) => {
                    if !finish_aead_worker_job(
                        job,
                        &opened,
                        &sealed,
                        &completion_tx,
                        &completion_notify,
                    ) {
                        break;
                    }
                }
                Err(_) => bulk_open = false,
            },
            recv(shutdown_rx) -> _ => break,
        }
    }
}

fn finish_aead_worker_job(
    job: AeadWorkerJob,
    opened: &StatelessAeadOpenWorker,
    sealed: &StatelessAeadSealWorker,
    completion_tx: &crossbeam_channel::Sender<CryptoCompletion>,
    completion_notify: &tokio::sync::Notify,
) -> bool {
    let sent = completion_tx.send(job.execute(opened, sealed)).is_ok();
    if sent {
        completion_notify.notify_one();
    }
    sent
}

fn default_aead_worker_count() -> usize {
    std::thread::available_parallelism().map_or(2, usize::from).max(2)
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
