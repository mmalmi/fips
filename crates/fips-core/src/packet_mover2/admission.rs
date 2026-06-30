#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionConfig {
    priority_capacity: usize,
    bulk_capacity: usize,
}

impl AdmissionConfig {
    pub(crate) fn new(priority_capacity: usize, bulk_capacity: usize) -> Self {
        Self {
            priority_capacity,
            bulk_capacity,
        }
    }

    pub(crate) fn total_capacity(self) -> usize {
        self.priority_capacity.saturating_add(self.bulk_capacity)
    }

    fn lane_capacity(self, lane: Lane) -> usize {
        match lane {
            Lane::Priority => self.priority_capacity,
            Lane::Bulk => self.bulk_capacity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDropReason {
    PriorityFull,
    BulkFull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionDrop {
    owner: OwnerId,
    counter: u64,
    class: PacketClass,
    lane: Lane,
    payload_len: usize,
    reason: AdmissionDropReason,
}

impl AdmissionDrop {
    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) fn class(&self) -> PacketClass {
        self.class
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> AdmissionDropReason {
        self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedPacket {
    ingress_seq: u64,
    packet: SocketPacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedOutboundPacket {
    ingress_seq: u64,
    packet: OutboundPacket,
}

trait OwnerQueuedAdmission {
    fn owner(&self) -> OwnerId;
    fn lane(&self) -> Lane;
    fn ingress_seq(&self) -> u64;
}

impl OwnerQueuedAdmission for QueuedPacket {
    fn owner(&self) -> OwnerId {
        self.packet.owner
    }

    fn lane(&self) -> Lane {
        self.packet.lane()
    }

    fn ingress_seq(&self) -> u64 {
        self.ingress_seq
    }
}

impl OwnerQueuedAdmission for QueuedOutboundPacket {
    fn owner(&self) -> OwnerId {
        self.packet.owner
    }

    fn lane(&self) -> Lane {
        self.packet.lane()
    }

    fn ingress_seq(&self) -> u64 {
        self.ingress_seq
    }
}

#[derive(Debug)]
struct OwnerLaneQueues<T> {
    priority: VecDeque<T>,
    bulk: VecDeque<T>,
}

impl<T> Default for OwnerLaneQueues<T> {
    fn default() -> Self {
        Self {
            priority: VecDeque::new(),
            bulk: VecDeque::new(),
        }
    }
}

impl<T> OwnerLaneQueues<T> {
    fn lane(&self, lane: Lane) -> &VecDeque<T> {
        match lane {
            Lane::Priority => &self.priority,
            Lane::Bulk => &self.bulk,
        }
    }

    fn lane_mut(&mut self, lane: Lane) -> &mut VecDeque<T> {
        match lane {
            Lane::Priority => &mut self.priority,
            Lane::Bulk => &mut self.bulk,
        }
    }

    fn is_empty(&self) -> bool {
        self.priority.is_empty() && self.bulk.is_empty()
    }
}

#[derive(Debug)]
struct OwnerAdmissionQueues<T> {
    priority_len: usize,
    bulk_len: usize,
    priority_ready: VecDeque<OwnerId>,
    bulk_ready: VecDeque<OwnerId>,
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
            priority_ready: VecDeque::new(),
            bulk_ready: VecDeque::new(),
            owners: HashMap::new(),
        }
    }

    fn lens(&self) -> (usize, usize) {
        (self.priority_len, self.bulk_len)
    }

    fn len(&self) -> usize {
        self.priority_len.saturating_add(self.bulk_len)
    }

    fn push_back(&mut self, item: T) {
        self.push(item, false);
    }

    fn push_front(&mut self, item: T) {
        self.push(item, true);
    }

    fn push(&mut self, item: T, front: bool) {
        let owner = item.owner();
        let lane = item.lane();
        let was_empty = {
            let queue = self.owners.entry(owner).or_default().lane_mut(lane);
            let was_empty = queue.is_empty();
            if front {
                queue.push_front(item);
            } else {
                queue.push_back(item);
            }
            was_empty
        };
        self.increment_lane_len(lane);
        if was_empty {
            self.push_ready_back(lane, owner);
        }
    }

    fn pop_next(&mut self) -> Option<OwnerAdmissionPop<T>> {
        self.pop_lane(Lane::Priority)
            .or_else(|| self.pop_lane(Lane::Bulk))
    }

    fn pop_next_priority(&mut self) -> Option<OwnerAdmissionPop<T>> {
        self.pop_lane(Lane::Priority)
    }

    fn peek_next_seq(&self) -> Option<u64> {
        self.peek_lane_seq(Lane::Priority)
            .or_else(|| self.peek_lane_seq(Lane::Bulk))
    }

    fn peek_next_priority_seq(&self) -> Option<u64> {
        self.peek_lane_seq(Lane::Priority)
    }

    fn has_priority_pending(&self) -> bool {
        self.priority_len > 0
    }

    fn peek_lane_seq(&self, lane: Lane) -> Option<u64> {
        let ready = match lane {
            Lane::Priority => &self.priority_ready,
            Lane::Bulk => &self.bulk_ready,
        };
        ready.iter().find_map(|owner| {
            self.owners
                .get(owner)
                .and_then(|queues| queues.lane(lane).front())
                .map(OwnerQueuedAdmission::ingress_seq)
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
        let item = queues.lane_mut(lane).pop_front()?;
        let owner_has_more = !queues.lane(lane).is_empty();
        let owner_empty = queues.is_empty();
        Some((item, owner_has_more, owner_empty))
    }

    fn increment_lane_len(&mut self, lane: Lane) {
        match lane {
            Lane::Priority => self.priority_len = self.priority_len.saturating_add(1),
            Lane::Bulk => self.bulk_len = self.bulk_len.saturating_add(1),
        }
    }

    fn decrement_lane_len(&mut self, lane: Lane) {
        match lane {
            Lane::Priority => self.priority_len = self.priority_len.saturating_sub(1),
            Lane::Bulk => self.bulk_len = self.bulk_len.saturating_sub(1),
        }
    }

    fn pop_ready_front(&mut self, lane: Lane) -> Option<OwnerId> {
        match lane {
            Lane::Priority => self.priority_ready.pop_front(),
            Lane::Bulk => self.bulk_ready.pop_front(),
        }
    }

    fn push_ready_back(&mut self, lane: Lane, owner: OwnerId) {
        match lane {
            Lane::Priority => self.priority_ready.push_back(owner),
            Lane::Bulk => self.bulk_ready.push_back(owner),
        }
    }

    fn push_ready_front(&mut self, lane: Lane, owner: OwnerId) {
        match lane {
            Lane::Priority => self.priority_ready.push_front(owner),
            Lane::Bulk => self.bulk_ready.push_front(owner),
        }
    }

    fn continue_owner_run(&mut self, cursor: OwnerAdmissionCursor) {
        if cursor.owner_has_more {
            self.push_ready_front(cursor.lane, cursor.owner);
        }
    }

    fn defer_owner_pop(&mut self, pop: OwnerAdmissionPop<T>) {
        let owner = pop.cursor.owner;
        let lane = pop.cursor.lane;
        self.owners
            .entry(owner)
            .or_default()
            .lane_mut(lane)
            .push_front(pop.item);
        self.increment_lane_len(lane);
        self.push_ready_back(lane, owner);
    }
}

#[derive(Debug)]
pub(crate) struct AdmissionQueue {
    queues: OwnerAdmissionQueues<QueuedPacket>,
}

impl AdmissionQueue {
    pub(crate) fn new() -> Self {
        Self {
            queues: OwnerAdmissionQueues::new(),
        }
    }

    fn admit_with_seq(&mut self, packet: SocketPacket, ingress_seq: u64) -> u64 {
        self.queues.push_back(QueuedPacket {
            ingress_seq,
            packet,
        });
        ingress_seq
    }

    fn pop_next(&mut self) -> Option<OwnerAdmissionPop<QueuedPacket>> {
        self.queues.pop_next()
    }

    fn pop_next_priority(&mut self) -> Option<OwnerAdmissionPop<QueuedPacket>> {
        self.queues.pop_next_priority()
    }

    fn peek_next_seq(&self) -> Option<u64> {
        self.queues.peek_next_seq()
    }

    fn peek_next_priority_seq(&self) -> Option<u64> {
        self.queues.peek_next_priority_seq()
    }

    fn continue_owner_run(&mut self, cursor: OwnerAdmissionCursor) {
        self.queues.continue_owner_run(cursor);
    }

    fn defer_owner_pop(&mut self, pop: OwnerAdmissionPop<QueuedPacket>) {
        self.queues.defer_owner_pop(pop);
    }

    fn len(&self) -> usize {
        self.queues.len()
    }

    fn has_priority_pending(&self) -> bool {
        self.queues.has_priority_pending()
    }

    fn lens(&self) -> (usize, usize) {
        self.queues.lens()
    }

}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundAdmissionDrop {
    owner: OwnerId,
    class: PacketClass,
    lane: Lane,
    payload_len: usize,
    reason: AdmissionDropReason,
}

impl OutboundAdmissionDrop {
    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn class(&self) -> PacketClass {
        self.class
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> AdmissionDropReason {
        self.reason
    }
}

#[derive(Debug)]
pub(crate) struct OutboundAdmissionQueue {
    queues: OwnerAdmissionQueues<QueuedOutboundPacket>,
}

impl OutboundAdmissionQueue {
    pub(crate) fn new() -> Self {
        Self {
            queues: OwnerAdmissionQueues::new(),
        }
    }

    fn admit_with_seq(&mut self, packet: OutboundPacket, ingress_seq: u64) -> u64 {
        self.queues.push_back(QueuedOutboundPacket {
            ingress_seq,
            packet,
        });
        ingress_seq
    }

    fn pop_next(&mut self) -> Option<OwnerAdmissionPop<QueuedOutboundPacket>> {
        self.queues.pop_next()
    }

    fn pop_next_priority(&mut self) -> Option<OwnerAdmissionPop<QueuedOutboundPacket>> {
        self.queues.pop_next_priority()
    }

    fn peek_next_seq(&self) -> Option<u64> {
        self.queues.peek_next_seq()
    }

    fn peek_next_priority_seq(&self) -> Option<u64> {
        self.queues.peek_next_priority_seq()
    }

    fn continue_owner_run(&mut self, cursor: OwnerAdmissionCursor) {
        self.queues.continue_owner_run(cursor);
    }

    fn defer_owner_pop(&mut self, pop: OwnerAdmissionPop<QueuedOutboundPacket>) {
        self.queues.defer_owner_pop(pop);
    }

    fn has_priority_pending(&self) -> bool {
        self.queues.has_priority_pending()
    }

    fn len(&self) -> usize {
        self.queues.len()
    }

    fn lens(&self) -> (usize, usize) {
        self.queues.lens()
    }

}
