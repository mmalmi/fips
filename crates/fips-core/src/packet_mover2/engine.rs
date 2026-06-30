#[derive(Debug)]
pub(crate) struct PacketMover2 {
    config: AdmissionConfig,
    shards: Vec<PacketMover2OwnerShard>,
    next_ingress_seq: u64,
    next_outbound_seq: u64,
    preferred_ingress_dispatch_shard: Option<usize>,
    preferred_outbound_dispatch_shard: Option<usize>,
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
        let shards = (0..shard_count).map(|_| PacketMover2OwnerShard::new()).collect();
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
        let admitted = self
            .owner_shard_mut(packet.owner)
            .submit_socket_packet_with_seq(packet, ingress_seq);
        Ok(admitted)
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
        let admitted = self
            .owner_shard_mut(packet.owner)
            .submit_outbound_packet_with_seq(packet, ingress_seq);
        Ok(admitted)
    }

    fn retire_completion(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        self.owner_shard_mut(completion.reservation.owner)
            .retire_completion(completion)
    }

    fn run_aead_available_into_with_executor<E>(
        &mut self,
        limit: usize,
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
            self.dispatch_prepared_available_into(
                pre_priority_inbound_limit,
                prepared_work,
                &mut fsp_path_open,
                &mut fsp_path_open_bulk,
            );
        dispatched_total = dispatched_total.saturating_add(pre_priority_inbound_dispatched);
        priority_feed_capacity =
            priority_feed_capacity.saturating_sub(pre_priority_inbound_dispatched);

        let priority_outbound_limit = outbound_priority_reserve
            .min(limit.saturating_sub(dispatched_total))
            .min(priority_feed_capacity);
        let priority_outbound_dispatched =
            self.dispatch_outbound_prepared_priority_available_into(
                priority_outbound_limit,
                prepared_work,
            );
        dispatched_total = dispatched_total.saturating_add(priority_outbound_dispatched);
        priority_feed_capacity = priority_feed_capacity.saturating_sub(priority_outbound_dispatched);

        let priority_inbound_limit = if inbound_priority_pending {
            priority_feed_capacity
        } else {
            0
        };
        let priority_inbound_dispatched =
            self.dispatch_prepared_priority_available_into(
                priority_inbound_limit,
                prepared_work,
                &mut fsp_path_open,
                &mut fsp_path_open_bulk,
            );
        dispatched_total = dispatched_total.saturating_add(priority_inbound_dispatched);

        let total_remaining = total_available_limit.saturating_sub(dispatched_total);
        bulk_feed_capacity = bulk_feed_capacity.min(total_remaining);
        let bulk_dispatch_capacity = limit
            .saturating_sub(dispatched_total)
            .min(bulk_feed_capacity);
        let bulk_inbound_start = prepared_work.len();
        let inbound_dispatched = self.dispatch_prepared_available_into(
            bulk_dispatch_capacity,
            prepared_work,
            &mut fsp_path_open,
            &mut fsp_path_open_bulk,
        );
        dispatched_total = dispatched_total.saturating_add(inbound_dispatched);
        bulk_feed_capacity = bulk_feed_capacity.saturating_sub(inbound_dispatched);
        let outbound_start = prepared_work.len();
        let outbound_dispatched =
            self.dispatch_outbound_prepared_available_into(bulk_feed_capacity, prepared_work);
        dispatched_total = dispatched_total.saturating_add(outbound_dispatched);
        debug_assert!(dispatched_total <= total_available_limit);

        let leading_priority_seals = prepared_work[outbound_start..]
            .iter()
            .take_while(|work| work.lane() == Lane::Priority)
            .count();
        if leading_priority_seals > 0 {
            prepared_work[bulk_inbound_start..outbound_start + leading_priority_seals]
                .rotate_right(leading_priority_seals);
        }
        record_fsp_path_open_dispatch(fsp_path_open, fsp_path_open_bulk);

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

    fn dispatch_prepared_available_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        fsp_path_open: &mut u64,
        fsp_path_open_bulk: &mut u64,
    ) -> usize {
        self.dispatch_prepared_ingress_shards_into(
            limit,
            prepared,
            false,
            fsp_path_open,
            fsp_path_open_bulk,
        )
    }

    fn dispatch_prepared_priority_available_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        fsp_path_open: &mut u64,
        fsp_path_open_bulk: &mut u64,
    ) -> usize {
        self.dispatch_prepared_ingress_shards_into(
            limit,
            prepared,
            true,
            fsp_path_open,
            fsp_path_open_bulk,
        )
    }

    fn dispatch_outbound_prepared_available_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
    ) -> usize {
        self.dispatch_outbound_prepared_shards_into(limit, prepared, false)
    }

    fn dispatch_outbound_prepared_priority_available_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
    ) -> usize {
        self.dispatch_outbound_prepared_shards_into(limit, prepared, true)
    }

    fn dispatch_prepared_ingress_shards_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        priority_only: bool,
        fsp_path_open: &mut u64,
        fsp_path_open_bulk: &mut u64,
    ) -> usize {
        if limit == 0 || self.shards.is_empty() {
            crate::perf_profile::record_packet_mover2_crypto_open_batch(0);
            return 0;
        }

        let start_len = prepared.len();
        let mut dispatched = 0usize;
        let mut attempts_remaining = self.admission_len_for_priority(priority_only);
        let mut skipped_shards = PacketMover2ShardSkipSet::empty();
        while dispatched < limit && attempts_remaining > 0 {
            let Some(shard) = self.select_ingress_dispatch_shard(priority_only, &skipped_shards)
            else {
                break;
            };
            let got = self.shards[shard].dispatch_ingress_prepared_into(
                limit.saturating_sub(dispatched),
                prepared,
                priority_only,
                fsp_path_open,
                fsp_path_open_bulk,
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
        crate::perf_profile::record_packet_mover2_crypto_open_batch(
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
            crate::perf_profile::record_packet_mover2_crypto_seal_batch(0);
            return 0;
        }

        let start_len = prepared.len();
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

            match self.shards[shard].dispatch_outbound_prepared_into(item, prepared) {
                OutboundDispatchResult::Completed => {
                    self.shards[shard].continue_outbound_owner_run(cursor);
                    self.preferred_outbound_dispatch_shard = Some(shard);
                    skipped_shards.clear();
                    if prepared.len().saturating_sub(start_len) > dispatched {
                        dispatched = prepared.len().saturating_sub(start_len);
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

        crate::perf_profile::record_packet_mover2_crypto_seal_batch(
            prepared.len().saturating_sub(start_len),
        );
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
