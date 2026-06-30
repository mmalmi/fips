#[derive(Debug)]
pub(crate) struct PacketMover2 {
    config: AdmissionConfig,
    shards: Vec<PacketMover2OwnerShard>,
    next_ingress_seq: u64,
    next_outbound_seq: u64,
    preferred_ingress_dispatch_shard: Option<usize>,
    preferred_outbound_dispatch_shard: Option<usize>,
}

#[derive(Debug)]
struct PacketMover2OwnerShard {
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
    drops: Vec<PacketDrop>,
}

enum OutboundDispatchResult {
    Completed,
    Blocked(QueuedOutboundPacket),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PacketMover2ShardSkipSet(usize);

impl PacketMover2ShardSkipSet {
    fn empty() -> Self {
        Self(0)
    }

    fn contains(self, shard: usize) -> bool {
        shard < usize::BITS as usize && (self.0 & (1usize << shard)) != 0
    }

    fn insert(&mut self, shard: usize) {
        if shard < usize::BITS as usize {
            self.0 |= 1usize << shard;
        }
    }

    fn clear(&mut self) {
        self.0 = 0;
    }
}

impl PacketMover2 {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        let shard_count = packet_mover2_owner_shard_count(config);
        let shards = (0..shard_count)
            .map(|_| PacketMover2OwnerShard::new(config))
            .collect();
        Self {
            config,
            shards,
            next_ingress_seq: 0,
            next_outbound_seq: 0,
            preferred_ingress_dispatch_shard: None,
            preferred_outbound_dispatch_shard: None,
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

    pub(crate) fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.owner_shard(owner).owner_active_path(owner)
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owner_shard_mut(owner).owner_mut(owner)
    }

    pub(crate) fn submit_socket_packet(
        &mut self,
        packet: SocketPacket,
    ) -> Result<u64, AdmissionDrop> {
        let lane = packet.lane();
        if self.admission_lane_len(lane) >= self.config.lane_capacity(lane) {
            let drop = AdmissionDrop {
                owner: packet.owner,
                counter: packet.counter,
                class: packet.class,
                lane,
                payload_len: packet.payload.len(),
                reason: match lane {
                    Lane::Priority => AdmissionDropReason::PriorityFull,
                    Lane::Bulk => AdmissionDropReason::BulkFull,
                },
            };
            self.record_drop(drop.clone().into());
            return Err(drop);
        }

        let ingress_seq = self.next_ingress_seq();
        self.owner_shard_mut(packet.owner)
            .submit_socket_packet_with_seq(packet, ingress_seq)
    }

    fn submit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
    ) -> Result<u64, OutboundAdmissionDrop> {
        let lane = packet.lane();
        if self.outbound_admission_lane_len(lane) >= self.config.lane_capacity(lane) {
            let drop = OutboundAdmissionDrop {
                owner: packet.owner,
                class: packet.class,
                lane,
                payload_len: packet.payload.len(),
                reason: match lane {
                    Lane::Priority => AdmissionDropReason::PriorityFull,
                    Lane::Bulk => AdmissionDropReason::BulkFull,
                },
            };
            self.record_drop(drop.clone().into());
            return Err(drop);
        }

        let ingress_seq = self.next_outbound_seq();
        self.owner_shard_mut(packet.owner)
            .submit_outbound_packet_with_seq(packet, ingress_seq)
    }

    fn dispatch_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> usize {
        work.clear();
        self.dispatch_ingress_shards_into(limit, work, false)
    }

    fn dispatch_priority_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> usize {
        work.clear();
        self.dispatch_ingress_shards_into(limit, work, true)
    }

    fn dispatch_outbound_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> usize {
        work.clear();
        self.dispatch_outbound_shards_into(limit, work, false)
    }

    fn dispatch_outbound_priority_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> usize {
        work.clear();
        self.dispatch_outbound_shards_into(limit, work, true)
    }

    fn retire_completion(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        self.owner_shard_mut(completion.reservation.owner)
            .retire_completion(completion)
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
        let total_available_limit = limit.min(executor_capacity);
        let priority_available_limit =
            limit.min(executor.available_capacity_for_lane(Lane::Priority));
        let bulk_available_limit = limit.min(executor.available_capacity_for_lane(Lane::Bulk));
        let mut priority_feed_capacity = priority_available_limit.min(total_available_limit);
        let mut bulk_feed_capacity = bulk_available_limit.min(total_available_limit);
        let inbound_priority_pending = self.has_inbound_priority_pending();
        let outbound_priority_reserve =
            outbound_priority_dispatch_limit(
                priority_feed_capacity,
                self.has_outbound_priority_pending(),
            );
        let pre_priority_inbound_limit =
            inbound_before_outbound_priority_limit(priority_feed_capacity, outbound_priority_reserve);
        let mut dispatched_total = 0usize;
        let mut fsp_path_open = 0u64;
        let mut fsp_path_open_bulk = 0u64;

        let pre_priority_inbound_dispatched =
            self.dispatch_available_into(pre_priority_inbound_limit, open_work);
        dispatched_total = dispatched_total.saturating_add(pre_priority_inbound_dispatched);
        priority_feed_capacity =
            priority_feed_capacity.saturating_sub(pre_priority_inbound_dispatched);
        self.append_open_work_batch(
            open_work,
            prepared_work,
            &mut fsp_path_open,
            &mut fsp_path_open_bulk,
        );

        let priority_outbound_limit = outbound_priority_reserve
            .min(limit.saturating_sub(dispatched_total))
            .min(priority_feed_capacity);
        let priority_outbound_dispatched =
            self.dispatch_outbound_priority_available_into(priority_outbound_limit, seal_work);
        dispatched_total = dispatched_total.saturating_add(priority_outbound_dispatched);
        priority_feed_capacity = priority_feed_capacity.saturating_sub(priority_outbound_dispatched);
        self.append_seal_work_batch(seal_work.drain(..), prepared_work);

        let priority_inbound_limit = if inbound_priority_pending {
            priority_feed_capacity
        } else {
            0
        };
        let priority_inbound_dispatched =
            self.dispatch_priority_available_into(priority_inbound_limit, open_work);
        dispatched_total = dispatched_total.saturating_add(priority_inbound_dispatched);
        self.append_open_work_batch(
            open_work,
            prepared_work,
            &mut fsp_path_open,
            &mut fsp_path_open_bulk,
        );

        let total_remaining = total_available_limit.saturating_sub(dispatched_total);
        bulk_feed_capacity = bulk_feed_capacity.min(total_remaining);
        let bulk_dispatch_capacity = limit
            .saturating_sub(dispatched_total)
            .min(bulk_feed_capacity);
        let inbound_dispatched = self.dispatch_available_into(bulk_dispatch_capacity, open_work);
        dispatched_total = dispatched_total.saturating_add(inbound_dispatched);
        bulk_feed_capacity = bulk_feed_capacity.saturating_sub(inbound_dispatched);
        let outbound_dispatched =
            self.dispatch_outbound_available_into(bulk_feed_capacity, seal_work);
        dispatched_total = dispatched_total.saturating_add(outbound_dispatched);
        debug_assert!(dispatched_total <= total_available_limit);

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

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        let mut drops = Vec::new();
        for shard in &mut self.shards {
            drops.extend(shard.drain_drops());
        }
        drops
    }

    pub(crate) fn admission_queue_lens(&self) -> (usize, usize) {
        self.shards.iter().fold((0usize, 0usize), |sum, shard| {
            let lens = shard.admission_queue_lens();
            (sum.0.saturating_add(lens.0), sum.1.saturating_add(lens.1))
        })
    }

    pub(crate) fn outbound_admission_queue_lens(&self) -> (usize, usize) {
        self.shards.iter().fold((0usize, 0usize), |sum, shard| {
            let lens = shard.outbound_admission_queue_lens();
            (sum.0.saturating_add(lens.0), sum.1.saturating_add(lens.1))
        })
    }

    fn owner_shard_index(&self, owner: OwnerId) -> usize {
        packet_mover2_owner_shard_index(owner, self.shards.len())
    }

    fn owner_shard(&self, owner: OwnerId) -> &PacketMover2OwnerShard {
        &self.shards[self.owner_shard_index(owner)]
    }

    fn owner_shard_mut(&mut self, owner: OwnerId) -> &mut PacketMover2OwnerShard {
        let shard = self.owner_shard_index(owner);
        &mut self.shards[shard]
    }

    fn owner_state(&self, owner: OwnerId) -> Option<&OwnerState> {
        self.owner_shard(owner).owner(owner)
    }

    fn owner_crypto_keys(&self, owner: OwnerId) -> Option<OwnerCryptoKeys> {
        self.owner_state(owner).and_then(OwnerState::crypto_keys)
    }

    fn record_drop(&mut self, drop: PacketDrop) {
        self.owner_shard_mut(drop.owner).drops.push(drop);
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

    fn admission_lane_len(&self, lane: Lane) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.admission_lane_len(lane))
            .sum()
    }

    fn outbound_admission_lane_len(&self, lane: Lane) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.outbound_admission_lane_len(lane))
            .sum()
    }

    fn has_inbound_priority_pending(&self) -> bool {
        self.shards
            .iter()
            .any(PacketMover2OwnerShard::has_inbound_priority_pending)
    }

    fn has_outbound_priority_pending(&self) -> bool {
        self.shards
            .iter()
            .any(PacketMover2OwnerShard::has_outbound_priority_pending)
    }

    fn dispatch_ingress_shards_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
        priority_only: bool,
    ) -> usize {
        if limit == 0 || self.shards.is_empty() {
            return 0;
        }

        let mut dispatched = 0usize;
        let mut attempts_remaining = self.admission_len_for_priority(priority_only);
        let mut skipped_shards = PacketMover2ShardSkipSet::empty();
        while dispatched < limit && attempts_remaining > 0 {
            let Some(shard) = self.select_ingress_dispatch_shard(priority_only, &skipped_shards)
            else {
                break;
            };
            let got = self.shards[shard].dispatch_ingress_available_into(
                limit.saturating_sub(dispatched),
                work,
                priority_only,
            );
            dispatched = dispatched.saturating_add(got);
            if got == 0 {
                self.preferred_ingress_dispatch_shard = None;
                skipped_shards.insert(shard);
                attempts_remaining = attempts_remaining.saturating_sub(1);
            } else {
                self.preferred_ingress_dispatch_shard = Some(shard);
                skipped_shards.clear();
                attempts_remaining = self.admission_len_for_priority(priority_only);
            }
        }
        dispatched
    }

    fn dispatch_outbound_shards_into(
        &mut self,
        limit: usize,
        work: &mut Vec<OutboundCryptoWork>,
        priority_only: bool,
    ) -> usize {
        if limit == 0 || self.shards.is_empty() {
            return 0;
        }

        let mut dispatched = 0usize;
        let mut attempts_remaining = self.outbound_len();
        let mut skipped_shards = PacketMover2ShardSkipSet::empty();
        while dispatched < limit && attempts_remaining > 0 {
            let Some(shard) = self.select_outbound_dispatch_shard(priority_only, &skipped_shards)
            else {
                break;
            };
            let pop = if priority_only {
                self.shards[shard].pop_outbound_priority()
            } else {
                self.shards[shard].pop_outbound()
            };
            let Some(OwnerAdmissionPop { item, cursor }) = pop else {
                self.preferred_outbound_dispatch_shard = None;
                skipped_shards.insert(shard);
                attempts_remaining = attempts_remaining.saturating_sub(1);
                continue;
            };
            attempts_remaining = attempts_remaining.saturating_sub(1);

            match self.dispatch_queued_outbound(item, work) {
                OutboundDispatchResult::Completed => {
                    self.shards[shard].continue_outbound_owner_run(cursor);
                    self.preferred_outbound_dispatch_shard = Some(shard);
                    skipped_shards.clear();
                    if work.len() > dispatched {
                        dispatched = work.len();
                    }
                    attempts_remaining = self.outbound_len();
                }
                OutboundDispatchResult::Blocked(queued) => {
                    self.shards[shard].defer_outbound_owner_pop(OwnerAdmissionPop {
                        item: queued,
                        cursor,
                    });
                    self.preferred_outbound_dispatch_shard = None;
                }
            }
        }

        dispatched.min(limit)
    }

    fn outbound_len(&self) -> usize {
        self.shards
            .iter()
            .map(PacketMover2OwnerShard::outbound_len)
            .sum()
    }

    fn admission_len_for_priority(&self, priority_only: bool) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.admission_len_for_priority(priority_only))
            .sum()
    }

    fn select_ingress_dispatch_shard(
        &self,
        priority_only: bool,
        skipped_shards: &PacketMover2ShardSkipSet,
    ) -> Option<usize> {
        let priority_only = priority_only || self.has_inbound_priority_pending();
        if let Some(shard) = self.preferred_ingress_dispatch_shard
            && !skipped_shards.contains(shard)
            && self
                .shards
                .get(shard)
                .and_then(|shard| shard.peek_ingress_seq(priority_only))
                .is_some()
        {
            return Some(shard);
        }
        self.shards
            .iter()
            .enumerate()
            .filter(|(shard, _)| !skipped_shards.contains(*shard))
            .filter_map(|(shard, owner_shard)| {
                owner_shard
                    .peek_ingress_seq(priority_only)
                    .map(|seq| (seq, shard))
            })
            .min_by_key(|(seq, _)| *seq)
            .map(|(_, shard)| shard)
    }

    fn select_outbound_dispatch_shard(
        &self,
        priority_only: bool,
        skipped_shards: &PacketMover2ShardSkipSet,
    ) -> Option<usize> {
        let priority_only = priority_only || self.has_outbound_priority_pending();
        if let Some(shard) = self.preferred_outbound_dispatch_shard
            && !skipped_shards.contains(shard)
            && self
                .shards
                .get(shard)
                .and_then(|shard| shard.peek_outbound_seq(priority_only))
                .is_some()
        {
            return Some(shard);
        }
        self.shards
            .iter()
            .enumerate()
            .filter(|(shard, _)| !skipped_shards.contains(*shard))
            .filter_map(|(shard, owner_shard)| {
                owner_shard
                    .peek_outbound_seq(priority_only)
                    .map(|seq| (seq, shard))
            })
            .min_by_key(|(seq, _)| *seq)
            .map(|(_, shard)| shard)
    }

    fn dispatch_queued_outbound(
        &mut self,
        queued: QueuedOutboundPacket,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> OutboundDispatchResult {
        let owner_id = queued.packet.owner;
        let lane = queued.packet.lane();
        let class = queued.packet.class;
        let ingress_seq = queued.ingress_seq;
        let wrap_route = match queued.packet.post_seal {
            OutboundPostSeal::FmpWrap(route) => Some(route),
            OutboundPostSeal::Transport => None,
        };

        let Some(owner) = self.owner_state(owner_id) else {
            self.record_drop(PacketDrop::from_queued_outbound(
                &queued,
                PacketDropReason::UnknownOwner,
            ));
            return OutboundDispatchResult::Completed;
        };
        if !owner.can_reserve_class(class) {
            record_owner_blocked(owner.reserve_block_reason(class));
            return OutboundDispatchResult::Blocked(queued);
        }

        if let Some(route) = wrap_route {
            let outer_owner_id = route.fmp_owner;
            let Some(outer_owner) = self.owner_state(outer_owner_id) else {
                self.record_drop(PacketDrop {
                    owner: outer_owner_id,
                    counter: None,
                    ingress_seq: Some(ingress_seq),
                    lane,
                    reason: PacketDropReason::UnknownOwner,
                    crypto_failure: None,
                    wire_flags: None,
                    authenticated_counter_highest: None,
                });
                return OutboundDispatchResult::Completed;
            };
            if !outer_owner.can_reserve_class(class) {
                record_owner_blocked(outer_owner.reserve_block_reason(class));
                return OutboundDispatchResult::Blocked(queued);
            }
        }

        let (reservation, packet) = {
            let owner = self
                .owner_mut(owner_id)
                .expect("outbound owner checked before reservation");
            match owner.reserve_outbound(queued.packet, ingress_seq) {
                Ok(reserved) => reserved,
                Err(error) => {
                    self.record_drop(PacketDrop {
                        owner: owner_id,
                        counter: None,
                        ingress_seq: Some(ingress_seq),
                        lane,
                        reason: error.into(),
                        crypto_failure: None,
                        wire_flags: None,
                        authenticated_counter_highest: None,
                    });
                    return OutboundDispatchResult::Completed;
                }
            }
        };

        let Some(route) = wrap_route else {
            work.push(OutboundCryptoWork::new(reservation, packet));
            return OutboundDispatchResult::Completed;
        };

        let mut outer_packet = route.reserve_fmp_outbound(class);
        if let Some(tick) = packet.activity_tick {
            outer_packet = outer_packet.with_activity_tick(tick);
        }
        let outer_owner_id = route.fmp_owner;
        let outer_reserved = {
            let Some(outer_owner) = self.owner_mut(outer_owner_id) else {
                self.release_reserved_outbound(reservation);
                self.record_drop(PacketDrop {
                    owner: outer_owner_id,
                    counter: None,
                    ingress_seq: Some(ingress_seq),
                    lane,
                    reason: PacketDropReason::UnknownOwner,
                    crypto_failure: None,
                    wire_flags: None,
                    authenticated_counter_highest: None,
                });
                return OutboundDispatchResult::Completed;
            };
            match outer_owner.reserve_outbound(outer_packet, ingress_seq) {
                Ok(reserved) => reserved,
                Err(error) => {
                    self.release_reserved_outbound(reservation);
                    self.record_drop(PacketDrop {
                        owner: outer_owner_id,
                        counter: None,
                        ingress_seq: Some(ingress_seq),
                        lane,
                        reason: error.into(),
                        crypto_failure: None,
                        wire_flags: None,
                        authenticated_counter_highest: None,
                    });
                    return OutboundDispatchResult::Completed;
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
        OutboundDispatchResult::Completed
    }

    fn release_reserved_outbound(&mut self, reservation: OwnerReservation) {
        let retired = self.retire_completion(failed_crypto_completion(
            reservation,
            CryptoFailureKind::Seal,
        ));
        for item in retired {
            if let RetiredPacket::Drop(drop) = item {
                self.record_drop(drop);
            }
        }
    }

    fn prepare_seal_work(&mut self, work: OutboundCryptoWork) -> PreparedCryptoWork {
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

    fn owner(&self, owner: OwnerId) -> Option<&OwnerState> {
        self.owners.get(&owner)
    }

    fn submit_socket_packet_with_seq(
        &mut self,
        packet: SocketPacket,
        ingress_seq: u64,
    ) -> Result<u64, AdmissionDrop> {
        match self.admission.admit_with_seq(packet, ingress_seq) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
    }

    fn submit_outbound_packet_with_seq(
        &mut self,
        packet: OutboundPacket,
        ingress_seq: u64,
    ) -> Result<u64, OutboundAdmissionDrop> {
        match self.outbound_admission.admit_with_seq(packet, ingress_seq) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
    }

    fn dispatch_ingress_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
        priority_only: bool,
    ) -> usize {
        let start_len = work.len();
        let target_len = start_len.saturating_add(limit);
        let mut attempts_remaining = self.admission.len();
        while work.len() < target_len && attempts_remaining > 0 {
            let pop = if priority_only {
                self.admission.pop_next_priority()
            } else {
                self.admission.pop_next()
            };
            let Some(pop) = pop else {
                if !priority_only && limit > 0 {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::PacketMover2DispatchNoIngress,
                    );
                }
                break;
            };
            attempts_remaining = attempts_remaining.saturating_sub(1);
            let OwnerAdmissionPop {
                item: queued,
                cursor,
            } = pop;

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                self.admission.continue_owner_run(cursor);
                continue;
            };
            if !owner.can_reserve_class(queued.packet.class) {
                record_owner_blocked(owner.reserve_block_reason(queued.packet.class));
                self.admission.defer_owner_pop(OwnerAdmissionPop {
                    item: queued,
                    cursor,
                });
                continue;
            }

            match owner.reserve(&queued.packet, queued.ingress_seq) {
                Ok(reservation) => {
                    work.push(CryptoWork {
                        reservation,
                        packet: queued.packet,
                    });
                    self.admission.continue_owner_run(cursor);
                    attempts_remaining = self.admission.len();
                }
                Err(error) => {
                    self.drops
                        .push(PacketDrop::from_queued(&queued, error.into()));
                    self.admission.continue_owner_run(cursor);
                }
            }
        }

        let dispatched = work.len().saturating_sub(start_len);
        if !priority_only && limit > 0 && dispatched >= limit {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PacketMover2DispatchLimitHit,
            );
        }
        dispatched
    }

    fn has_inbound_priority_pending(&self) -> bool {
        self.admission.has_priority_pending()
    }

    fn has_outbound_priority_pending(&self) -> bool {
        self.outbound_admission.has_priority_pending()
    }

    fn admission_len_for_priority(&self, priority_only: bool) -> usize {
        if priority_only {
            self.admission_lane_len(Lane::Priority)
        } else {
            self.admission.len()
        }
    }

    fn peek_ingress_seq(&self, priority_only: bool) -> Option<u64> {
        if priority_only {
            self.admission.peek_next_priority_seq()
        } else {
            self.admission.peek_next_seq()
        }
    }

    fn peek_outbound_seq(&self, priority_only: bool) -> Option<u64> {
        if priority_only {
            self.outbound_admission.peek_next_priority_seq()
        } else {
            self.outbound_admission.peek_next_seq()
        }
    }

    fn admission_lane_len(&self, lane: Lane) -> usize {
        let lens = self.admission.lens();
        match lane {
            Lane::Priority => lens.0,
            Lane::Bulk => lens.1,
        }
    }

    fn outbound_admission_lane_len(&self, lane: Lane) -> usize {
        let lens = self.outbound_admission.lens();
        match lane {
            Lane::Priority => lens.0,
            Lane::Bulk => lens.1,
        }
    }

    fn outbound_len(&self) -> usize {
        self.outbound_admission.len()
    }

    fn pop_outbound(&mut self) -> Option<OwnerAdmissionPop<QueuedOutboundPacket>> {
        self.outbound_admission.pop_next()
    }

    fn pop_outbound_priority(&mut self) -> Option<OwnerAdmissionPop<QueuedOutboundPacket>> {
        self.outbound_admission.pop_next_priority()
    }

    fn continue_outbound_owner_run(&mut self, cursor: OwnerAdmissionCursor) {
        self.outbound_admission.continue_owner_run(cursor);
    }

    fn defer_outbound_owner_pop(&mut self, pop: OwnerAdmissionPop<QueuedOutboundPacket>) {
        self.outbound_admission.defer_owner_pop(pop);
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

    fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    fn admission_queue_lens(&self) -> (usize, usize) {
        self.admission.lens()
    }

    fn outbound_admission_queue_lens(&self) -> (usize, usize) {
        self.outbound_admission.lens()
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

fn packet_mover2_owner_shard_count(config: AdmissionConfig) -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
        .min(usize::BITS as usize)
        .min(config.total_capacity().max(1))
        .max(1)
}

fn packet_mover2_owner_shard_index(owner: OwnerId, shards: usize) -> usize {
    use std::hash::{Hash, Hasher};

    let shards = shards.max(1);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    owner.node_addr().hash(&mut hasher);
    (hasher.finish() as usize) % shards
}
