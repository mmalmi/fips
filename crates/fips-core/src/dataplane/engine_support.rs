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

    fn lane(self, lane: Lane) -> usize {
        match lane {
            Lane::Priority => self.priority,
            Lane::Bulk => self.bulk,
        }
    }

    fn increment(&mut self, lane: Lane) {
        self.increment_by(lane, 1);
    }

    fn increment_by(&mut self, lane: Lane, count: usize) {
        match lane {
            Lane::Priority => self.priority = self.priority.saturating_add(count),
            Lane::Bulk => self.bulk = self.bulk.saturating_add(count),
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

#[derive(Clone, Debug)]
struct ReadyShardQueue {
    queue: VecDeque<usize>,
    ready: Vec<bool>,
}

impl ReadyShardQueue {
    fn new(shards: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            ready: vec![false; shards],
        }
    }

    fn mark(&mut self, shard: usize) {
        let Some(is_ready) = self.ready.get_mut(shard) else {
            return;
        };
        if *is_ready {
            return;
        }
        *is_ready = true;
        self.queue.push_back(shard);
    }

    fn pop(&mut self) -> Option<usize> {
        loop {
            let shard = self.queue.pop_front()?;
            let Some(is_ready) = self.ready.get_mut(shard) else {
                continue;
            };
            if !*is_ready {
                continue;
            }
            *is_ready = false;
            return Some(shard);
        }
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn has_ready(&self) -> bool {
        !self.queue.is_empty()
    }
}

#[derive(Clone, Debug)]
struct ReadyShardQueues {
    priority: ReadyShardQueue,
    bulk: ReadyShardQueue,
}

impl ReadyShardQueues {
    fn new(shards: usize) -> Self {
        Self {
            priority: ReadyShardQueue::new(shards),
            bulk: ReadyShardQueue::new(shards),
        }
    }

    fn mark(&mut self, shard: usize, lane: Lane) {
        self.lane_mut(lane).mark(shard);
    }

    fn mark_from_lens(&mut self, shard: usize, lens: LaneLens) {
        if lens.priority > 0 {
            self.mark(shard, Lane::Priority);
        }
        if lens.bulk > 0 {
            self.mark(shard, Lane::Bulk);
        }
    }

    fn pop(&mut self, priority_only: bool) -> Option<usize> {
        self.pop_lane(Lane::Priority).or_else(|| {
            if priority_only {
                None
            } else {
                self.pop_lane(Lane::Bulk)
            }
        })
    }

    fn ready_len(&self, priority_only: bool) -> usize {
        if priority_only {
            self.priority.len()
        } else {
            self.priority.len().saturating_add(self.bulk.len())
        }
    }

    fn has_ready(&self) -> bool {
        self.priority.has_ready() || self.bulk.has_ready()
    }

    fn pop_lane(&mut self, lane: Lane) -> Option<usize> {
        self.lane_mut(lane).pop()
    }

    fn lane_mut(&mut self, lane: Lane) -> &mut ReadyShardQueue {
        match lane {
            Lane::Priority => &mut self.priority,
            Lane::Bulk => &mut self.bulk,
        }
    }
}

fn record_ingress_owner_blocked(reason: Option<OwnerReserveBlockReason>) {
    record_owner_blocked(
        crate::perf_profile::Event::DataplaneDispatchIngressOwnerBlocked,
        reason,
    );
}

fn record_outbound_owner_blocked(reason: Option<OwnerReserveBlockReason>) {
    record_owner_blocked(
        crate::perf_profile::Event::DataplaneDispatchOutboundOwnerBlocked,
        reason,
    );
}

fn record_owner_blocked(
    source_event: crate::perf_profile::Event,
    reason: Option<OwnerReserveBlockReason>,
) {
    use crate::perf_profile::{record_event, Event};

    record_event(Event::DataplaneDispatchOwnerBlocked);
    record_event(source_event);
    match reason {
        Some(OwnerReserveBlockReason::TotalInFlight) => {
            record_event(Event::DataplaneDispatchOwnerBlockedTotal);
        }
        Some(OwnerReserveBlockReason::BulkLane) => {
            record_event(Event::DataplaneDispatchOwnerBlockedBulkLane);
        }
        None => {}
    }
}

fn socket_packet_run_owner_lane(packets: &[SocketPacket]) -> Option<(OwnerId, Lane)> {
    let first = packets.first()?;
    let owner = first.owner;
    let lane = first.lane();
    packets
        .iter()
        .all(|packet| packet.owner == owner && packet.lane() == lane)
        .then_some((owner, lane))
}

fn outbound_packet_run_owner_lane(packets: &[OutboundPacket]) -> Option<(OwnerId, Lane)> {
    let first = packets.first()?;
    let owner = first.owner;
    let lane = first.lane();
    packets
        .iter()
        .all(|packet| packet.owner == owner && packet.lane() == lane)
        .then_some((owner, lane))
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

struct FspPathOpenDispatch {
    enabled: bool,
    total: u64,
    bulk: u64,
}

impl FspPathOpenDispatch {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            total: 0,
            bulk: 0,
        }
    }

    fn count(&mut self, reservation: &OwnerReservation) {
        if !self.enabled || reservation.owner.protocol() != PacketProtocol::Fsp {
            return;
        }
        self.total += 1;
        if reservation.lane == Lane::Bulk {
            self.bulk += 1;
        }
    }

    fn record(self) {
        if self.total == 0 {
            return;
        }
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneFspPathOpen,
            self.total,
        );
        if self.bulk > 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::DataplaneFspPathOpenBulk,
                self.bulk,
            );
        }
    }
}

fn dataplane_owner_shard_count(config: AdmissionConfig) -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
        .min(usize::BITS as usize)
        .min(config.total_capacity().max(1))
        .max(1)
}

fn dataplane_owner_shard_dispatch_quantum(remaining: usize, shard_count: usize) -> usize {
    let shard_count = shard_count.max(1);
    remaining.saturating_add(shard_count - 1) / shard_count
}

fn dataplane_ingress_owner_shard_dispatch_limit(
    remaining: usize,
    ready_lanes: usize,
    priority_only: bool,
) -> usize {
    if priority_only {
        dataplane_owner_shard_dispatch_quantum(remaining, ready_lanes)
    } else {
        remaining
    }
}

fn dataplane_owner_shard_index(owner: OwnerId, shards: usize) -> usize {
    let shards = shards.max(1);
    // NodeAddr is SHA-256-derived, so its bytes are already suitable for sharding.
    let node = u128::from_le_bytes(*owner.node_addr().as_bytes());
    let mixed = node ^ (node >> 64);
    (mixed as usize) % shards
}
