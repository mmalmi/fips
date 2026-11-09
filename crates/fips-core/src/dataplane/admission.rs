#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionConfig {
    priority_capacity: usize,
    bulk_capacity: usize,
    background_capacity: usize,
}

impl AdmissionConfig {
    pub(crate) fn new(priority_capacity: usize, bulk_capacity: usize) -> Self {
        Self {
            priority_capacity,
            bulk_capacity,
            background_capacity: bulk_capacity.min(64),
        }
    }

    pub(crate) fn total_capacity(self) -> usize {
        self.priority_capacity
            .saturating_add(self.bulk_capacity)
            .saturating_add(self.background_capacity)
    }

    fn lane_capacity(self, lane: Lane) -> usize {
        match lane {
            Lane::Priority => self.priority_capacity,
            Lane::Bulk => self.bulk_capacity,
            Lane::Background => self.background_capacity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDropReason {
    Priority,
    Bulk,
    Background,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionDrop {
    owner: OwnerId,
    received_carrier: Option<(TransportPath, ActivityTick)>,
    counter: Option<u64>,
    send_token: Option<u64>,
    reason: AdmissionDropReason,
}

impl AdmissionDrop {
    fn inbound(packet: &SocketPacket) -> Self {
        Self {
            owner: packet.owner,
            received_carrier: packet.source_path.clone().zip(packet.activity_tick),
            counter: Some(packet.counter),
            send_token: None,
            reason: admission_drop_reason(packet.lane()),
        }
    }

    fn outbound(packet: &OutboundPacket) -> Self {
        Self {
            owner: packet.owner,
            received_carrier: None,
            counter: None,
            send_token: packet.send_token,
            reason: admission_drop_reason(packet.lane()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedAdmission<P> {
    ingress_seq: u64,
    enqueued_at: tokio::time::Instant,
    packet: P,
}

type QueuedPacket = QueuedAdmission<SocketPacket>;
type QueuedOutboundPacket = QueuedAdmission<OutboundPacket>;

pub(crate) type AdmissionQueue = PacketAdmissionQueue<SocketPacket>;
pub(crate) type OutboundAdmissionQueue = PacketAdmissionQueue<OutboundPacket>;

pub(crate) trait AdmissionPacket {
    fn owner(&self) -> OwnerId;
    fn lane(&self) -> Lane;
    fn bid(&self) -> u64 { 0 }
}

trait OwnerQueuedAdmission {
    fn bid(&self) -> u64;
    fn owner(&self) -> OwnerId;
    fn lane(&self) -> Lane;
}

impl AdmissionPacket for SocketPacket {
    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn lane(&self) -> Lane {
        self.lane()
    }
}

impl AdmissionPacket for OutboundPacket {
    fn bid(&self) -> u64 {
        match self.class { PacketClass::Paid(rate) => rate.get(), _ => 0 }
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn lane(&self) -> Lane {
        self.lane()
    }
}

impl<P> OwnerQueuedAdmission for QueuedAdmission<P>
where
    P: AdmissionPacket,
{
    fn owner(&self) -> OwnerId {
        self.packet.owner()
    }

    fn bid(&self) -> u64 { self.packet.bid() }

    fn lane(&self) -> Lane {
        self.packet.lane()
    }
}

#[derive(Debug)]
struct OwnerLaneQueues<T> {
    priority: VecDeque<T>,
    bulk: VecDeque<T>,
    background: VecDeque<T>,
}

impl<T> Default for OwnerLaneQueues<T> {
    fn default() -> Self {
        Self {
            priority: VecDeque::new(),
            bulk: VecDeque::new(),
            background: VecDeque::new(),
        }
    }
}

impl<T> OwnerLaneQueues<T> {
    fn lane_mut(&mut self, lane: Lane) -> &mut VecDeque<T> {
        match lane {
            Lane::Priority => &mut self.priority,
            Lane::Bulk => &mut self.bulk,
            Lane::Background => &mut self.background,
        }
    }

    fn is_empty(&self) -> bool {
        self.priority.is_empty() && self.bulk.is_empty() && self.background.is_empty()
    }
}

#[derive(Debug)]
struct OwnerAdmissionQueues<T> {
    priority_len: usize,
    bulk_len: usize,
    background_len: usize,
    priority_ready: VecDeque<OwnerId>,
    bulk_ready: VecDeque<OwnerId>,
    background_ready: VecDeque<OwnerId>,
    bulk_cut_in_debt: u8,
    ranked_len: usize,
    owners: HashMap<OwnerId, OwnerLaneQueues<T>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnerAdmissionCursor {
    owner: OwnerId,
    lane: Lane,
    owner_has_more: bool,
}

#[derive(Debug)]
struct OwnerAdmissionPop<T> {
    item: T,
    cursor: OwnerAdmissionCursor,
}

impl<T> OwnerAdmissionQueues<T>
where
    T: OwnerQueuedAdmission,
{
    fn new() -> Self {
        Self {
            priority_len: 0,
            bulk_len: 0,
            background_len: 0,
            priority_ready: VecDeque::new(),
            bulk_ready: VecDeque::new(),
            background_ready: VecDeque::new(),
            bulk_cut_in_debt: 0,
            ranked_len: 0,
            owners: HashMap::new(),
        }
    }

    fn lens(&self) -> (usize, usize, usize) {
        (self.priority_len, self.bulk_len, self.background_len)
    }

    fn len(&self) -> usize {
        self.priority_len.saturating_add(self.bulk_len).saturating_add(self.background_len)
    }

    // The queue is bounded by normal data admission. Equal bids preserve FIFO;
    // a deferred reservation resumes before new packets of the same price.
    fn insert_by_bid(queue: &mut VecDeque<T>, item: T, front: bool) {
        let bid = item.bid();
        if !front && bid == 0 {
            queue.push_back(item);
        } else {
            let index = queue.partition_point(|old| {
                if front { old.bid() > bid } else { old.bid() >= bid }
            });
            queue.insert(index, item);
        }
    }

    fn push_run_back<I>(&mut self, owner: OwnerId, lane: Lane, items: I) -> bool
    where
        I: IntoIterator<Item = T>,
    {
        let mut pushed = 0usize;
        let was_empty = {
            let queue = self.owners.entry(owner).or_default().lane_mut(lane);
            let was_empty = queue.is_empty();
            for item in items {
                debug_assert_eq!(item.owner(), owner);
                debug_assert_eq!(item.lane(), lane);
                self.ranked_len += usize::from(item.bid() > 0);
                Self::insert_by_bid(queue, item, false);
                pushed = pushed.saturating_add(1);
            }
            was_empty
        };
        if pushed == 0 {
            return false;
        }
        self.increment_lane_len_by(lane, pushed);
        if was_empty {
            self.push_ready(lane, owner, dataplane_local_bulk(owner, lane));
        }
        was_empty
    }

    fn push(&mut self, item: T, front: bool) -> bool {
        let owner = item.owner();
        let lane = item.lane();
        let was_empty = {
            let queue = self.owners.entry(owner).or_default().lane_mut(lane);
            let was_empty = queue.is_empty();
            self.ranked_len += usize::from(item.bid() > 0);
            Self::insert_by_bid(queue, item, front);
            was_empty
        };
        self.increment_lane_len_by(lane, 1);
        if was_empty {
            self.push_ready(lane, owner, dataplane_local_bulk(owner, lane));
        }
        was_empty
    }

    fn pop_next_run_into(
        &mut self,
        lane: Lane,
        limit: usize,
        items: &mut Vec<T>,
    ) -> Option<OwnerAdmissionCursor> {
        if limit == 0 {
            return None;
        }
        debug_assert!(items.is_empty());

        let first = self.pop_lane(lane)?;
        let mut cursor = first.cursor;
        items.reserve(limit.min(self.len().saturating_add(1)));
        items.push(first.item);

        let first_bid = items[0].bid();
        while items.len() < limit && cursor.owner_has_more {
            if first_bid > 0 && self.owners.get(&cursor.owner)
                .and_then(|q| q.bulk.front()).is_some_and(|next| next.bid() < first_bid) {
                break;
            }
            let Some(next) = self.pop_owner_continue(cursor) else {
                cursor.owner_has_more = false;
                break;
            };
            cursor = next.cursor;
            items.push(next.item);
        }

        Some(cursor)
    }

    fn pop_owner_continue(
        &mut self,
        cursor: OwnerAdmissionCursor,
    ) -> Option<OwnerAdmissionPop<T>> {
        if !cursor.owner_has_more {
            return None;
        }
        let (item, owner_has_more, owner_empty) =
            self.pop_owner_lane(cursor.owner, cursor.lane)?;
        self.decrement_lane_len(cursor.lane);
        if owner_empty {
            self.owners.remove(&cursor.owner);
        }
        Some(OwnerAdmissionPop {
            item,
            cursor: OwnerAdmissionCursor {
                owner: cursor.owner,
                lane: cursor.lane,
                owner_has_more,
            },
        })
    }

    fn pop_lane(&mut self, lane: Lane) -> Option<OwnerAdmissionPop<T>> {
        loop {
            let owner = self.pop_ready_front(lane)?;
            let Some((item, owner_has_more, owner_empty)) = self.pop_owner_lane(owner, lane) else {
                continue;
            };
            self.decrement_lane_len(lane);
            if owner_empty {
                self.owners.remove(&owner);
            }
            return Some(OwnerAdmissionPop {
                item,
                cursor: OwnerAdmissionCursor {
                    owner,
                    lane,
                    owner_has_more,
                },
            });
        }
    }

    fn pop_owner_lane(&mut self, owner: OwnerId, lane: Lane) -> Option<(T, bool, bool)> {
        let queues = self.owners.get_mut(&owner)?;
        let queue = queues.lane_mut(lane);
        let item = queue.pop_front()?;
        self.ranked_len -= usize::from(item.bid() > 0);
        let owner_has_more = !queue.is_empty();
        let owner_empty = queues.is_empty();
        Some((item, owner_has_more, owner_empty))
    }

    fn increment_lane_len_by(&mut self, lane: Lane, count: usize) {
        match lane {
            Lane::Priority => self.priority_len = self.priority_len.saturating_add(count),
            Lane::Bulk => self.bulk_len = self.bulk_len.saturating_add(count),
            Lane::Background => self.background_len = self.background_len.saturating_add(count),
        }
    }

    fn decrement_lane_len(&mut self, lane: Lane) {
        match lane {
            Lane::Priority => self.priority_len = self.priority_len.saturating_sub(1),
            Lane::Bulk => self.bulk_len = self.bulk_len.saturating_sub(1),
            Lane::Background => self.background_len = self.background_len.saturating_sub(1),
        }
    }

    fn pop_ready_front(&mut self, lane: Lane) -> Option<OwnerId> {
        let owner = match lane {
            Lane::Priority => self.priority_ready.pop_front(),
            Lane::Bulk if self.ranked_len != 0 => {
                let mut best = 0;
                let mut best_bid = 0;
                for (index, owner) in self.bulk_ready.iter().enumerate() {
                    let bid = self.owners.get(owner).and_then(|q| q.bulk.front()).map_or(0, T::bid);
                    if bid > best_bid {
                        best = index;
                        best_bid = bid;
                    }
                }
                self.bulk_ready.remove(best)
            }
            Lane::Bulk => self.bulk_ready.pop_front(),
            Lane::Background => self.background_ready.pop_front(),
        }?;
        if lane == Lane::Bulk {
            self.bulk_cut_in_debt = self.bulk_cut_in_debt.saturating_sub(1);
        }
        Some(owner)
    }

    fn push_ready(&mut self, lane: Lane, owner: OwnerId, front: bool) {
        let ready = match lane {
            Lane::Priority => &mut self.priority_ready,
            Lane::Bulk => &mut self.bulk_ready,
            Lane::Background => &mut self.background_ready,
        };
        if ready.contains(&owner) {
            return;
        }
        if front && !ready.is_empty() && self.bulk_cut_in_debt == 0 {
            ready.push_front(owner);
            self.bulk_cut_in_debt = 2;
        } else {
            ready.push_back(owner);
        }
    }

    fn ready_lens(&self) -> (usize, usize, usize) {
        (self.priority_ready.len(), self.bulk_ready.len(), self.background_ready.len())
    }

    fn continue_owner_lane(&mut self, cursor: OwnerAdmissionCursor) {
        if cursor.owner_has_more {
            self.push_ready(cursor.lane, cursor.owner, false);
        }
    }

    fn defer_owner_run(&mut self, cursor: OwnerAdmissionCursor, items: &mut Vec<T>) {
        let count = items.len();
        if count == 0 {
            return;
        }
        let queue = self
            .owners
            .entry(cursor.owner)
            .or_default()
            .lane_mut(cursor.lane);
        for item in items.drain(..).rev() {
            self.ranked_len += usize::from(item.bid() > 0);
            Self::insert_by_bid(queue, item, true);
        }
        self.increment_lane_len_by(cursor.lane, count);
    }

    fn wake_owner(&mut self, owner: OwnerId) {
        let Some(queues) = self.owners.get(&owner) else {
            return;
        };
        let priority_ready = !queues.priority.is_empty();
        let bulk_ready = !queues.bulk.is_empty();
        let background_ready = !queues.background.is_empty();
        if priority_ready {
            self.push_ready(Lane::Priority, owner, false);
        }
        if bulk_ready {
            self.push_ready(Lane::Bulk, owner, dataplane_local_bulk(owner, Lane::Bulk));
        }
        if background_ready {
            self.push_ready(Lane::Background, owner, false);
        }
    }
}

#[derive(Debug)]
pub(crate) struct PacketAdmissionQueue<P> {
    queues: OwnerAdmissionQueues<QueuedAdmission<P>>,
}

impl<P> PacketAdmissionQueue<P>
where
    P: AdmissionPacket,
{
    pub(crate) fn new() -> Self {
        Self {
            queues: OwnerAdmissionQueues::new(),
        }
    }

    fn admit_with_seq(&mut self, packet: P, ingress_seq: u64) -> bool {
        self.queues.push(
            QueuedAdmission {
                ingress_seq,
                enqueued_at: tokio::time::Instant::now(),
                packet,
            },
            false,
        )
    }

    fn admit_run_with_seq(&mut self, packets: Vec<P>, first_seq: u64) -> bool {
        let Some(first) = packets.first() else {
            return false;
        };
        let owner = first.owner();
        let lane = first.lane();
        let mut ingress_seq = first_seq;
        let queued = packets.into_iter().map(move |packet| {
            let queued = QueuedAdmission {
                ingress_seq,
                enqueued_at: tokio::time::Instant::now(),
                packet,
            };
            ingress_seq = ingress_seq.wrapping_add(1);
            queued
        });
        self.queues.push_run_back(owner, lane, queued)
    }

    fn pop_next_run_into(
        &mut self,
        lane: Lane,
        limit: usize,
        items: &mut Vec<QueuedAdmission<P>>,
    ) -> Option<OwnerAdmissionCursor> {
        self.queues
            .pop_next_run_into(lane, limit, items)
    }

    fn continue_owner_lane(&mut self, cursor: OwnerAdmissionCursor) {
        self.queues.continue_owner_lane(cursor);
    }

    fn defer_owner_run(
        &mut self,
        cursor: OwnerAdmissionCursor,
        items: &mut Vec<QueuedAdmission<P>>,
    ) {
        self.queues.defer_owner_run(cursor, items);
    }

    fn len(&self) -> usize {
        self.queues.len()
    }

    fn lens(&self) -> (usize, usize, usize) {
        self.queues.lens()
    }

    fn ready_lens(&self) -> (usize, usize, usize) {
        self.queues.ready_lens()
    }

    fn wake_owner(&mut self, owner: OwnerId) {
        self.queues.wake_owner(owner);
    }
}

impl OutboundAdmissionQueue {
    /// Displace only a lower funded bid waiting for this same outgoing link.
    /// Dispatch has not assigned its nonce or submitted it to transport yet.
    fn displace_lower_bid(&mut self, incoming: &OutboundPacket) -> Option<AdmissionDrop> {
        let PacketClass::Paid(bid) = incoming.class else { return None; };
        let queue = &mut self.queues.owners.get_mut(&incoming.owner)?.bulk;
        let cheapest = queue.partition_point(|entry| entry.bid() != 0).checked_sub(1)?;
        if queue[cheapest].bid() >= bid.get() { return None; }
        let removed = queue.remove(cheapest)?;
        self.queues.bulk_len -= 1;
        self.queues.ranked_len -= 1;
        Some(AdmissionDrop::outbound(&removed.packet))
    }
}

fn admission_drop_reason(lane: Lane) -> AdmissionDropReason {
    match lane {
        Lane::Priority => AdmissionDropReason::Priority,
        Lane::Bulk => AdmissionDropReason::Bulk,
        Lane::Background => AdmissionDropReason::Background,
    }
}
