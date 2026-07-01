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
}

impl OwnerQueuedAdmission for QueuedPacket {
    fn owner(&self) -> OwnerId {
        self.packet.owner
    }

    fn lane(&self) -> Lane {
        self.packet.lane()
    }

}

impl OwnerQueuedAdmission for QueuedOutboundPacket {
    fn owner(&self) -> OwnerId {
        self.packet.owner
    }

    fn lane(&self) -> Lane {
        self.packet.lane()
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

#[derive(Debug)]
struct OwnerAdmissionRun<T> {
    items: Vec<T>,
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

    fn push_back(&mut self, item: T) -> bool {
        self.push(item, false)
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
                queue.push_back(item);
                pushed = pushed.saturating_add(1);
            }
            was_empty
        };
        if pushed == 0 {
            return false;
        }
        self.increment_lane_len_by(lane, pushed);
        if was_empty {
            self.push_ready_back(lane, owner);
        }
        was_empty
    }

    fn push_front(&mut self, item: T) -> bool {
        self.push(item, true)
    }

    fn push(&mut self, item: T, front: bool) -> bool {
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
        was_empty
    }

    fn pop_next(&mut self) -> Option<OwnerAdmissionPop<T>> {
        self.pop_lane(Lane::Priority)
            .or_else(|| self.pop_lane(Lane::Bulk))
    }

    fn pop_next_priority(&mut self) -> Option<OwnerAdmissionPop<T>> {
        self.pop_lane(Lane::Priority)
    }

    fn pop_next_run(&mut self, priority_only: bool, limit: usize) -> Option<OwnerAdmissionRun<T>> {
        if limit == 0 {
            return None;
        }

        let first = if priority_only {
            self.pop_next_priority()
        } else {
            self.pop_next()
        }?;
        let mut cursor = first.cursor;
        let mut items = Vec::with_capacity(limit.min(self.len().saturating_add(1)));
        items.push(first.item);

        while items.len() < limit && cursor.owner_has_more {
            let Some(next) = self.pop_owner_continue(cursor) else {
                cursor.owner_has_more = false;
                break;
            };
            cursor = next.cursor;
            items.push(next.item);
        }

        Some(OwnerAdmissionRun { items, cursor })
    }

    fn pop_owner_continue(
        &mut self,
        cursor: OwnerAdmissionCursor,
    ) -> Option<OwnerAdmissionPop<T>> {
        if !cursor.owner_has_more {
            return None;
        }
        let Some((item, owner_has_more, owner_empty)) =
            self.pop_owner_lane(cursor.owner, cursor.lane)
        else {
            return None;
        };
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
        let item = queues.lane_mut(lane).pop_front()?;
        let owner_has_more = !queues.lane(lane).is_empty();
        let owner_empty = queues.is_empty();
        Some((item, owner_has_more, owner_empty))
    }

    fn increment_lane_len(&mut self, lane: Lane) {
        self.increment_lane_len_by(lane, 1);
    }

    fn increment_lane_len_by(&mut self, lane: Lane, count: usize) {
        match lane {
            Lane::Priority => self.priority_len = self.priority_len.saturating_add(count),
            Lane::Bulk => self.bulk_len = self.bulk_len.saturating_add(count),
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
        let ready = match lane {
            Lane::Priority => &mut self.priority_ready,
            Lane::Bulk => &mut self.bulk_ready,
        };
        if !ready.contains(&owner) {
            ready.push_back(owner);
        }
    }

    fn ready_lens(&self) -> (usize, usize) {
        (self.priority_ready.len(), self.bulk_ready.len())
    }

    fn continue_owner_lane(&mut self, cursor: OwnerAdmissionCursor) {
        if cursor.owner_has_more {
            self.push_ready_back(cursor.lane, cursor.owner);
        }
    }

    fn defer_owner_run(&mut self, run: OwnerAdmissionRun<T>) {
        let owner = run.cursor.owner;
        let lane = run.cursor.lane;
        let count = run.items.len();
        if count == 0 {
            return;
        }
        let queue = self.owners.entry(owner).or_default().lane_mut(lane);
        for item in run.items.into_iter().rev() {
            queue.push_front(item);
        }
        self.increment_lane_len_by(lane, count);
    }

    fn wake_owner(&mut self, owner: OwnerId) {
        let Some(queues) = self.owners.get(&owner) else {
            return;
        };
        let priority_ready = !queues.priority.is_empty();
        let bulk_ready = !queues.bulk.is_empty();
        if priority_ready {
            self.push_ready_back(Lane::Priority, owner);
        }
        if bulk_ready {
            self.push_ready_back(Lane::Bulk, owner);
        }
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

    fn admit_with_seq(&mut self, packet: SocketPacket, ingress_seq: u64) -> bool {
        self.queues.push_back(QueuedPacket {
            ingress_seq,
            packet,
        })
    }

    fn admit_run_with_seq(&mut self, packets: Vec<SocketPacket>, first_seq: u64) -> bool {
        let Some(first) = packets.first() else {
            return false;
        };
        let owner = first.owner;
        let lane = first.lane();
        let mut ingress_seq = first_seq;
        let queued = packets.into_iter().map(move |packet| {
            let queued = QueuedPacket {
                ingress_seq,
                packet,
            };
            ingress_seq = ingress_seq.wrapping_add(1);
            queued
        });
        self.queues.push_run_back(owner, lane, queued)
    }

    fn pop_next_run(
        &mut self,
        priority_only: bool,
        limit: usize,
    ) -> Option<OwnerAdmissionRun<QueuedPacket>> {
        self.queues.pop_next_run(priority_only, limit)
    }

    fn continue_owner_lane(&mut self, cursor: OwnerAdmissionCursor) {
        self.queues.continue_owner_lane(cursor);
    }

    fn defer_owner_run(&mut self, run: OwnerAdmissionRun<QueuedPacket>) {
        self.queues.defer_owner_run(run);
    }

    fn len(&self) -> usize {
        self.queues.len()
    }

    fn lens(&self) -> (usize, usize) {
        self.queues.lens()
    }

    fn ready_lens(&self) -> (usize, usize) {
        self.queues.ready_lens()
    }

    fn wake_owner(&mut self, owner: OwnerId) {
        self.queues.wake_owner(owner);
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

    fn admit_with_seq(&mut self, packet: OutboundPacket, ingress_seq: u64) -> bool {
        self.queues.push_back(QueuedOutboundPacket {
            ingress_seq,
            packet,
        })
    }

    fn admit_run_with_seq(&mut self, packets: Vec<OutboundPacket>, first_seq: u64) -> bool {
        let Some(first) = packets.first() else {
            return false;
        };
        let owner = first.owner;
        let lane = first.lane();
        let mut ingress_seq = first_seq;
        let queued = packets.into_iter().map(move |packet| {
            let queued = QueuedOutboundPacket {
                ingress_seq,
                packet,
            };
            ingress_seq = ingress_seq.wrapping_add(1);
            queued
        });
        self.queues.push_run_back(owner, lane, queued)
    }

    fn pop_next_run(
        &mut self,
        priority_only: bool,
        limit: usize,
    ) -> Option<OwnerAdmissionRun<QueuedOutboundPacket>> {
        self.queues.pop_next_run(priority_only, limit)
    }

    fn continue_owner_lane(&mut self, cursor: OwnerAdmissionCursor) {
        self.queues.continue_owner_lane(cursor);
    }

    fn defer_owner_run(&mut self, run: OwnerAdmissionRun<QueuedOutboundPacket>) {
        self.queues.defer_owner_run(run);
    }

    fn len(&self) -> usize {
        self.queues.len()
    }

    fn lens(&self) -> (usize, usize) {
        self.queues.lens()
    }

    fn ready_lens(&self) -> (usize, usize) {
        self.queues.ready_lens()
    }

    fn wake_owner(&mut self, owner: OwnerId) {
        self.queues.wake_owner(owner);
    }
}
