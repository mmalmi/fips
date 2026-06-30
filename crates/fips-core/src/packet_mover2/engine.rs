#[derive(Debug)]
pub(crate) struct PacketMover2 {
    config: AdmissionConfig,
    shards: Vec<PacketMover2OwnerShard>,
    admission_lens: LaneLens,
    outbound_admission_lens: LaneLens,
    drops: Vec<PacketDrop>,
    next_ingress_seq: u64,
    next_outbound_seq: u64,
    next_ingress_dispatch_shard: usize,
    next_outbound_dispatch_shard: usize,
}

impl PacketMover2 {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        let shard_count = packet_mover2_owner_shard_count(config);
        let shards = (0..shard_count).map(|_| PacketMover2OwnerShard::new()).collect();
        Self {
            config,
            shards,
            admission_lens: LaneLens::default(),
            outbound_admission_lens: LaneLens::default(),
            drops: Vec::new(),
            next_ingress_seq: 0,
            next_outbound_seq: 0,
            next_ingress_dispatch_shard: 0,
            next_outbound_dispatch_shard: 0,
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

    pub(crate) fn owner_fsp_activity(
        &self,
        owner: OwnerId,
    ) -> Option<PacketMover2FspOwnerActivity> {
        self.owner_shard(owner).owner_fsp_activity(owner)
    }

    pub(crate) fn owner_fsp_send_context(
        &self,
        owner: OwnerId,
    ) -> Option<PacketMover2FspSendContext> {
        self.owner_shard(owner).owner_fsp_send_context(owner)
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
        owner: OwnerId,
        previous_hop: NodeAddr,
        msg_type: u8,
        body_len: usize,
        activity_tick: Option<ActivityTick>,
    ) -> bool {
        self.owner_shard_mut(owner).record_authenticated_fsp_session(
            owner,
            previous_hop,
            msg_type,
            body_len,
            activity_tick,
        )
    }

    pub(crate) fn record_fsp_decrypt_failure(&mut self, owner: OwnerId) -> Option<u32> {
        self.owner_shard_mut(owner)
            .record_fsp_decrypt_failure(owner)
    }

    pub(crate) fn record_fsp_data_sent(
        &mut self,
        owner: OwnerId,
        next_hop: NodeAddr,
        bytes: usize,
        tick: ActivityTick,
    ) -> bool {
        self.owner_shard_mut(owner)
            .record_fsp_data_sent(owner, next_hop, bytes, tick)
    }

    pub(crate) fn submit_socket_packet(
        &mut self,
        packet: SocketPacket,
    ) -> Result<u64, AdmissionDrop> {
        let lane = packet.lane();
        if self.admission_lens.lane(lane) >= self.config.lane_capacity(lane) {
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
        self.admission_lens.increment(lane);
        Ok(admitted)
    }

    fn submit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
    ) -> Result<u64, OutboundAdmissionDrop> {
        let lane = packet.lane();
        if self.outbound_admission_lens.lane(lane) >= self.config.lane_capacity(lane) {
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
        self.outbound_admission_lens.increment(lane);
        Ok(admitted)
    }

    fn retire_completion_into(
        &mut self,
        completion: CryptoCompletion,
        retired: &mut Vec<RetiredPacket>,
    ) {
        let shard = self.owner_shard_index(completion.reservation.owner);
        self.shards[shard].retire_completion_into(completion, retired, &mut self.drops);
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

        drops.append(&mut self.drops);
        dispatched_total
    }

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    pub(crate) fn admission_queue_lens(&self) -> (usize, usize) {
        self.admission_lens.as_tuple()
    }

    pub(crate) fn outbound_admission_queue_lens(&self) -> (usize, usize) {
        self.outbound_admission_lens.as_tuple()
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
        let priority_only = priority_only || self.has_inbound_priority_pending();
        let shard_count = self.shards.len();
        let start_shard = self.next_ingress_dispatch_shard % shard_count;
        let mut dispatched = 0usize;
        for offset in 0..shard_count {
            if dispatched >= limit {
                break;
            }
            let shard = (start_shard + offset) % shard_count;
            let before = LaneLens::from_tuple(self.shards[shard].admission_queue_lens());
            let got = self.shards[shard].dispatch_ingress_prepared_into(
                limit.saturating_sub(dispatched),
                prepared,
                priority_only,
                fsp_path_open,
                fsp_path_open_bulk,
                &mut self.drops,
            );
            let after = LaneLens::from_tuple(self.shards[shard].admission_queue_lens());
            self.admission_lens.saturating_sub_assign(before.saturating_sub(after));
            dispatched = dispatched.saturating_add(got);
            if got > 0 {
                self.next_ingress_dispatch_shard = (shard + 1) % shard_count;
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

        let priority_only = priority_only || self.has_outbound_priority_pending();
        let start_len = prepared.len();
        let shard_count = self.shards.len();
        let start_shard = self.next_outbound_dispatch_shard % shard_count;
        let mut dispatched = 0usize;
        for offset in 0..shard_count {
            if dispatched >= limit {
                break;
            }
            let shard = (start_shard + offset) % shard_count;
            let before = LaneLens::from_tuple(self.shards[shard].outbound_admission_queue_lens());
            let got = self.shards[shard].dispatch_outbound_prepared_into(
                limit.saturating_sub(dispatched),
                prepared,
                priority_only,
                &mut self.drops,
            );
            let after = LaneLens::from_tuple(self.shards[shard].outbound_admission_queue_lens());
            self.outbound_admission_lens
                .saturating_sub_assign(before.saturating_sub(after));
            dispatched = dispatched.saturating_add(got);
            if got > 0 {
                self.next_outbound_dispatch_shard = (shard + 1) % shard_count;
            }
        }

        crate::perf_profile::record_packet_mover2_crypto_seal_batch(
            prepared.len().saturating_sub(start_len),
        );
        dispatched.min(limit)
    }

    fn retire_completion_batch(
        &mut self,
        completions: &mut Vec<CryptoCompletion>,
        retired: &mut Vec<RetiredPacket>,
    ) {
        for completion in completions.drain(..) {
            self.retire_completion_into(completion, retired);
        }
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

    fn as_tuple(self) -> (usize, usize) {
        (self.priority, self.bulk)
    }

    fn lane(self, lane: Lane) -> usize {
        match lane {
            Lane::Priority => self.priority,
            Lane::Bulk => self.bulk,
        }
    }

    fn increment(&mut self, lane: Lane) {
        match lane {
            Lane::Priority => self.priority = self.priority.saturating_add(1),
            Lane::Bulk => self.bulk = self.bulk.saturating_add(1),
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
