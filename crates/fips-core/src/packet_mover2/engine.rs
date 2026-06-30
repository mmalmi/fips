#[derive(Debug)]
pub(crate) struct PacketMover2 {
    shard: PacketMover2OwnerShard,
}

#[derive(Debug)]
struct PacketMover2OwnerShard {
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
    drops: Vec<PacketDrop>,
}

impl PacketMover2 {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            shard: PacketMover2OwnerShard::new(config),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.shard.register_owner(owner, config);
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> bool {
        self.shard.unregister_owner(owner)
    }

    pub(crate) fn has_owner(&self, owner: OwnerId) -> bool {
        self.shard.has_owner(owner)
    }

    pub(crate) fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.shard.owner_active_path(owner)
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.shard.owner_mut(owner)
    }

    pub(crate) fn submit_socket_packet(
        &mut self,
        packet: SocketPacket,
    ) -> Result<u64, AdmissionDrop> {
        self.shard.submit_socket_packet(packet)
    }

    fn submit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
    ) -> Result<u64, OutboundAdmissionDrop> {
        self.shard.submit_outbound_packet(packet)
    }

    fn dispatch_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> usize {
        self.shard.dispatch_available_into(limit, work)
    }

    fn dispatch_outbound_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> usize {
        self.shard.dispatch_outbound_available_into(limit, work)
    }

    fn retire_completion(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        self.shard.retire_completion(completion)
    }

    fn run_aead_available_into_with_executor<E>(
        &mut self,
        limit: usize,
        open_work: &mut Vec<CryptoWork>,
        seal_work: &mut Vec<OutboundCryptoWork>,
        prepared_work: &mut Vec<PreparedCryptoWork>,
        completion_work: &mut Vec<CryptoCompletion>,
        retired: &mut Vec<RetiredPacket>,
        drops: &mut Vec<PacketDrop>,
        executor: &mut E,
    ) -> usize
    where
        E: PacketMover2CryptoExecutor,
    {
        self.shard.run_aead_available_into_with_executor(
            limit,
            open_work,
            seal_work,
            prepared_work,
            completion_work,
            retired,
            drops,
            executor,
        )
    }

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        self.shard.drain_drops()
    }

    pub(crate) fn admission_queue_lens(&self) -> (usize, usize) {
        self.shard.admission_queue_lens()
    }

    pub(crate) fn outbound_admission_queue_lens(&self) -> (usize, usize) {
        self.shard.outbound_admission_queue_lens()
    }
}

impl PacketMover2OwnerShard {
    fn new(config: AdmissionConfig) -> Self {
        Self {
            admission: AdmissionQueue::new(config),
            outbound_admission: OutboundAdmissionQueue::new(config),
            owners: HashMap::new(),
            drops: Vec::new(),
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

    fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.owners
            .get(&owner)
            .and_then(OwnerState::active_path)
    }

    fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owners.get_mut(&owner)
    }

    fn owner_crypto_keys(&self, owner: OwnerId) -> Option<OwnerCryptoKeys> {
        self.owners.get(&owner).and_then(OwnerState::crypto_keys)
    }

    fn submit_socket_packet(&mut self, packet: SocketPacket) -> Result<u64, AdmissionDrop> {
        match self.admission.admit(packet) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
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
                if limit > 0 {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::PacketMover2DispatchNoIngress,
                    );
                }
                break;
            };

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                continue;
            };
            if !owner.can_reserve_class(queued.packet.class) {
                record_owner_blocked(owner.reserve_block_reason(queued.packet.class));
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

        if limit > 0 && work.len() >= limit {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PacketMover2DispatchLimitHit,
            );
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

            if !self.dispatch_queued_outbound(queued, work) {
                break;
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

            if !self.dispatch_queued_outbound(queued, work) {
                break;
            }
        }

        work.len()
    }

    fn dispatch_queued_outbound(
        &mut self,
        queued: QueuedOutboundPacket,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> bool {
        let owner_id = queued.packet.owner;
        let lane = queued.packet.lane();
        let class = queued.packet.class;
        let ingress_seq = queued.ingress_seq;
        let wrap_route = match queued.packet.post_seal {
            OutboundPostSeal::FmpWrap(route) => Some(route),
            OutboundPostSeal::Transport => None,
        };

        let Some(owner) = self.owners.get(&owner_id) else {
            self.drops.push(PacketDrop::from_queued_outbound(
                &queued,
                PacketDropReason::UnknownOwner,
            ));
            return true;
        };
        if !owner.can_reserve_class(class) {
            record_owner_blocked(owner.reserve_block_reason(class));
            self.outbound_admission.push_front(queued);
            return false;
        }

        if let Some(route) = wrap_route {
            let outer_owner_id = route.fmp_owner;
            let Some(outer_owner) = self.owners.get(&outer_owner_id) else {
                self.drops.push(PacketDrop {
                    owner: outer_owner_id,
                    counter: None,
                    ingress_seq: Some(ingress_seq),
                    lane,
                    reason: PacketDropReason::UnknownOwner,
                    crypto_failure: None,
                    wire_flags: None,
                    authenticated_counter_highest: None,
                });
                return true;
            };
            if !outer_owner.can_reserve_class(class) {
                record_owner_blocked(outer_owner.reserve_block_reason(class));
                self.outbound_admission.push_front(queued);
                return false;
            }
        }

        let (reservation, packet) = {
            let owner = self
                .owners
                .get_mut(&owner_id)
                .expect("outbound owner checked before reservation");
            match owner.reserve_outbound(queued.packet, ingress_seq) {
                Ok(reserved) => reserved,
                Err(error) => {
                    self.drops.push(PacketDrop {
                        owner: owner_id,
                        counter: None,
                        ingress_seq: Some(ingress_seq),
                        lane,
                        reason: error.into(),
                        crypto_failure: None,
                        wire_flags: None,
                        authenticated_counter_highest: None,
                    });
                    return true;
                }
            }
        };

        let Some(route) = wrap_route else {
            work.push(OutboundCryptoWork::new(reservation, packet));
            return true;
        };

        let mut outer_packet = route.reserve_fmp_outbound(class);
        if let Some(tick) = packet.activity_tick {
            outer_packet = outer_packet.with_activity_tick(tick);
        }
        let outer_owner_id = route.fmp_owner;
        let outer_reserved = {
            let Some(outer_owner) = self.owners.get_mut(&outer_owner_id) else {
                self.release_reserved_outbound(reservation);
                self.drops.push(PacketDrop {
                    owner: outer_owner_id,
                    counter: None,
                    ingress_seq: Some(ingress_seq),
                    lane,
                    reason: PacketDropReason::UnknownOwner,
                    crypto_failure: None,
                    wire_flags: None,
                    authenticated_counter_highest: None,
                });
                return true;
            };
            match outer_owner.reserve_outbound(outer_packet, ingress_seq) {
                Ok(reserved) => reserved,
                Err(error) => {
                    self.release_reserved_outbound(reservation);
                    self.drops.push(PacketDrop {
                        owner: outer_owner_id,
                        counter: None,
                        ingress_seq: Some(ingress_seq),
                        lane,
                        reason: error.into(),
                        crypto_failure: None,
                        wire_flags: None,
                        authenticated_counter_highest: None,
                    });
                    return true;
                }
            }
        };
        let (outer_reservation, outer_packet) = outer_reserved;
        work.push(
            OutboundCryptoWork::new(reservation, packet).with_wrap(OutboundWrapReservation::new(
                route,
                outer_reservation,
                outer_packet,
            )),
        );
        true
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
                RetiredPacket::WrappedCompletion(_) => None,
                RetiredPacket::OwnerCompletion(_) => None,
            }));
        retired
    }

    fn release_reserved_outbound(&mut self, reservation: OwnerReservation) {
        let retired = self.retire_completion(failed_crypto_completion(
            reservation,
            CryptoFailureKind::Seal,
        ));
        self.drops
            .extend(retired.into_iter().filter_map(|item| match item {
                RetiredPacket::Drop(drop) => Some(drop),
                RetiredPacket::Output(_)
                | RetiredPacket::Outbound(_)
                | RetiredPacket::WrappedCompletion(_)
                | RetiredPacket::OwnerCompletion(_) => None,
            }));
    }

    pub(crate) fn run_aead_available_into_with_executor<E>(
        &mut self,
        limit: usize,
        open_work: &mut Vec<CryptoWork>,
        seal_work: &mut Vec<OutboundCryptoWork>,
        prepared_work: &mut Vec<PreparedCryptoWork>,
        completion_work: &mut Vec<CryptoCompletion>,
        retired: &mut Vec<RetiredPacket>,
        drops: &mut Vec<PacketDrop>,
        executor: &mut E,
    ) -> usize
    where
        E: PacketMover2CryptoExecutor,
    {
        retired.clear();
        open_work.clear();
        seal_work.clear();
        prepared_work.clear();
        completion_work.clear();
        let executor_capacity = executor.available_capacity();
        if limit > 0 && executor_capacity == 0 {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PacketMover2DispatchExecutorFull,
            );
        }
        let available_limit = limit.min(executor_capacity);
        let mut feed_capacity = available_limit;
        let outbound_priority_reserve =
            outbound_priority_dispatch_limit(
                available_limit,
                self.outbound_admission.has_priority_pending(),
            );
        let pre_priority_inbound_limit =
            inbound_before_outbound_priority_limit(available_limit, outbound_priority_reserve);
        let mut dispatched_total = 0usize;
        let mut fsp_path_open = 0u64;
        let mut fsp_path_open_bulk = 0u64;
        // Owners reserve order/counters before work leaves this shard. Build one
        // prepared feed in priority-aware order, then let stateless workers run
        // it; completion side effects come back through ordered owner retire.
        let pre_priority_inbound_dispatched = self.dispatch_available_into(
            pre_priority_inbound_limit.min(feed_capacity),
            open_work,
        );
        dispatched_total = dispatched_total.saturating_add(pre_priority_inbound_dispatched);
        feed_capacity = feed_capacity.saturating_sub(pre_priority_inbound_dispatched);
        self.append_open_work_batch(
            open_work,
            prepared_work,
            &mut fsp_path_open,
            &mut fsp_path_open_bulk,
        );

        let priority_outbound_limit = outbound_priority_reserve
            .min(limit.saturating_sub(dispatched_total))
            .min(feed_capacity);
        let priority_outbound_dispatched =
            self.dispatch_outbound_priority_available_into(priority_outbound_limit, seal_work);
        dispatched_total = dispatched_total.saturating_add(priority_outbound_dispatched);
        feed_capacity = feed_capacity.saturating_sub(priority_outbound_dispatched);
        self.append_seal_work_batch(seal_work.drain(..), prepared_work);

        let bulk_dispatch_capacity = limit.saturating_sub(dispatched_total).min(feed_capacity);
        let inbound_dispatched = self.dispatch_available_into(bulk_dispatch_capacity, open_work);
        dispatched_total = dispatched_total.saturating_add(inbound_dispatched);
        feed_capacity = feed_capacity.saturating_sub(inbound_dispatched);
        let outbound_dispatched =
            self.dispatch_outbound_available_into(feed_capacity, seal_work);
        dispatched_total = dispatched_total.saturating_add(outbound_dispatched);
        debug_assert!(dispatched_total <= available_limit);

        let leading_priority_seals = seal_work
            .iter()
            .take_while(|work| work.reservation.lane == Lane::Priority)
            .count();
        self.append_seal_work_batch(seal_work.drain(..leading_priority_seals), prepared_work);

        self.append_open_work_batch(
            open_work,
            prepared_work,
            &mut fsp_path_open,
            &mut fsp_path_open_bulk,
        );
        record_fsp_path_open_dispatch(fsp_path_open, fsp_path_open_bulk);

        self.append_seal_work_batch(seal_work.drain(..), prepared_work);
        execute_prepared_crypto_chunk(executor, prepared_work, completion_work);
        self.retire_completion_batch(completion_work, retired);

        drops.extend(self.drain_drops());
        dispatched_total
    }

    fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    fn admission_queue_lens(&self) -> (usize, usize) {
        (self.admission.priority.len(), self.admission.bulk.len())
    }

    fn outbound_admission_queue_lens(&self) -> (usize, usize) {
        (
            self.outbound_admission.priority.len(),
            self.outbound_admission.bulk.len(),
        )
    }

    fn prepare_seal_work(
        &mut self,
        work: OutboundCryptoWork,
    ) -> PreparedCryptoWork {
        let reservation = work.reservation.clone();
        let wrap_reservation = work.wrap.as_ref().map(|wrap| wrap.reservation.clone());
        let Some(keys) = self.owner_crypto_keys(reservation.owner) else {
            return match wrap_reservation {
                Some(outer) => PreparedCryptoWork::failed_wrapped(
                    reservation,
                    outer,
                    CryptoFailureKind::Seal,
                ),
                None => PreparedCryptoWork::failed(reservation, CryptoFailureKind::Seal),
            };
        };
        let Some(outer_reservation) = wrap_reservation else {
            return PreparedCryptoWork::seal(work, keys.seal);
        };
        match self.owner_crypto_keys(outer_reservation.owner) {
            Some(outer_keys) => PreparedCryptoWork::seal_wrapped(work, keys.seal, outer_keys.seal),
            None => PreparedCryptoWork::failed_wrapped(
                reservation,
                outer_reservation,
                CryptoFailureKind::Seal,
            ),
        }
    }

    fn append_open_work_batch(
        &mut self,
        open_work: &mut Vec<CryptoWork>,
        prepared: &mut Vec<PreparedCryptoWork>,
        fsp_path_open: &mut u64,
        fsp_path_open_bulk: &mut u64,
    ) {
        let mut prepared_count = 0usize;
        for work in open_work.drain(..) {
            let reservation = work.reservation.clone();
            count_fsp_path_open_dispatch(&reservation, fsp_path_open, fsp_path_open_bulk);
            let prepared_work = match self.owner_crypto_keys(reservation.owner) {
                Some(keys) => PreparedCryptoWork::open(work, keys.open),
                None => PreparedCryptoWork::failed(reservation, CryptoFailureKind::Open),
            };
            prepared.push(prepared_work);
            prepared_count = prepared_count.saturating_add(1);
        }
        crate::perf_profile::record_packet_mover2_crypto_open_batch(prepared_count);
    }

    fn append_seal_work_batch<I>(
        &mut self,
        seal_work: I,
        prepared: &mut Vec<PreparedCryptoWork>,
    ) where
        I: IntoIterator<Item = OutboundCryptoWork>,
    {
        let mut prepared_count = 0usize;
        for work in seal_work {
            let prepared_work = self.prepare_seal_work(work);
            prepared.push(prepared_work);
            prepared_count = prepared_count.saturating_add(1);
        }
        crate::perf_profile::record_packet_mover2_crypto_seal_batch(prepared_count);
    }

    fn retire_completion_batch(
        &mut self,
        completions: &mut Vec<CryptoCompletion>,
        retired: &mut Vec<RetiredPacket>,
    ) {
        for completion in completions.drain(..) {
            retired.extend(self.retire_completion(completion));
        }
    }

}

fn record_owner_blocked(reason: Option<OwnerReserveBlockReason>) {
    use crate::perf_profile::{record_event, Event};

    record_event(Event::PacketMover2DispatchOwnerBlocked);
    match reason {
        Some(OwnerReserveBlockReason::TotalInFlight) => {
            record_event(Event::PacketMover2DispatchOwnerBlockedTotal);
        }
        Some(OwnerReserveBlockReason::BulkLane) => {
            record_event(Event::PacketMover2DispatchOwnerBlockedBulkLane);
        }
        Some(OwnerReserveBlockReason::DiscardableBulk) => {
            record_event(Event::PacketMover2DispatchOwnerBlockedDiscardableBulk);
        }
        Some(OwnerReserveBlockReason::ReliableBulk) => {
            record_event(Event::PacketMover2DispatchOwnerBlockedReliableBulk);
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
    E: PacketMover2CryptoExecutor,
{
    let prepared_len = prepared.len();
    let accepted = executor.execute_prepared_chunk(prepared, completions);
    debug_assert_eq!(
        accepted, prepared_len,
        "PM2 crypto executor must accept an entire owner-reserved prepared chunk"
    );
    accepted
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
        crate::perf_profile::Event::PacketMover2FspPathOpen,
        total,
    );
    if bulk > 0 {
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::PacketMover2FspPathOpenBulk,
            bulk,
        );
    }
}
