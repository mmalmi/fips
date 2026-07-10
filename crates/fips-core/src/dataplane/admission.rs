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
    counter: Option<u64>,
    send_token: Option<u64>,
    reason: AdmissionDropReason,
}

impl AdmissionDrop {
    fn inbound(packet: &SocketPacket) -> Self {
        Self {
            owner: packet.owner,
            counter: Some(packet.counter),
            send_token: None,
            reason: admission_drop_reason(packet.lane()),
        }
    }

    fn outbound(packet: &OutboundPacket) -> Self {
        Self {
            owner: packet.owner,
            counter: None,
            send_token: packet.send_token,
            reason: admission_drop_reason(packet.lane()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedAdmission<P> {
    ingress_seq: u64,
    packet: P,
}

type QueuedPacket = QueuedAdmission<SocketPacket>;
type QueuedOutboundPacket = QueuedAdmission<OutboundPacket>;

pub(crate) type AdmissionQueue = PacketAdmissionQueue<SocketPacket>;
pub(crate) type OutboundAdmissionQueue = PacketAdmissionQueue<OutboundPacket>;

pub(crate) trait AdmissionPacket {
    fn owner(&self) -> OwnerId;
    fn lane(&self) -> Lane;
}

trait OwnerQueuedAdmission {
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
        self.increment_lane_len_by(lane, 1);
        if was_empty {
            self.push_ready_back(lane, owner);
        }
        was_empty
    }

    fn pop_next_run(&mut self, priority_only: bool, limit: usize) -> Option<OwnerAdmissionRun<T>> {
        if limit == 0 {
            return None;
        }

        let first = if priority_only {
            self.pop_lane(Lane::Priority)
        } else {
            self.pop_lane(Lane::Priority)
                .or_else(|| self.pop_lane(Lane::Bulk))
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
        let owner_has_more = !queue.is_empty();
        let owner_empty = queues.is_empty();
        Some((item, owner_has_more, owner_empty))
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
    ) -> Option<OwnerAdmissionRun<QueuedAdmission<P>>> {
        self.queues.pop_next_run(priority_only, limit)
    }

    fn continue_owner_lane(&mut self, cursor: OwnerAdmissionCursor) {
        self.queues.continue_owner_lane(cursor);
    }

    fn defer_owner_run(&mut self, run: OwnerAdmissionRun<QueuedAdmission<P>>) {
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

fn admission_drop_reason(lane: Lane) -> AdmissionDropReason {
    match lane {
        Lane::Priority => AdmissionDropReason::PriorityFull,
        Lane::Bulk => AdmissionDropReason::BulkFull,
    }
}
