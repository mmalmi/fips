use super::{AdmissionDrop, AdmissionDropReason, PacketLane};
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::Relaxed},
};
use tokio::sync::mpsc::Receiver;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QueueCaps {
    pub(crate) priority_packets: usize,
    pub(crate) bulk_packets: usize,
}

impl QueueCaps {
    pub(crate) fn new(priority_packets: usize, bulk_packets: usize) -> Self {
        Self {
            priority_packets: priority_packets.max(1),
            bulk_packets: bulk_packets.max(1),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LaneCreditGate {
    lane: PacketLane,
    queued_packets: Arc<AtomicUsize>,
    capacity: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaneCreditReservation {
    lane: PacketLane,
    packet_count: usize,
}

impl LaneCreditReservation {
    pub(crate) fn lane(self) -> PacketLane {
        self.lane
    }

    pub(crate) fn packet_count(self) -> usize {
        self.packet_count
    }
}

impl LaneCreditGate {
    pub(crate) fn new(lane: PacketLane, capacity: usize) -> Self {
        Self {
            lane,
            queued_packets: Arc::new(AtomicUsize::new(0)),
            capacity: capacity.max(1),
        }
    }

    pub(crate) fn reserve(
        &self,
        packet_count: usize,
        byte_count: usize,
    ) -> Result<LaneCreditReservation, AdmissionDrop> {
        let packet_count = packet_count.max(1);
        self.reserve_with_previous(packet_count, byte_count)
            .map(|(reservation, _previous)| reservation)
    }

    pub(crate) fn reserve_with_previous(
        &self,
        packet_count: usize,
        byte_count: usize,
    ) -> Result<(LaneCreditReservation, usize), AdmissionDrop> {
        if packet_count == 0 {
            return Ok((
                LaneCreditReservation {
                    lane: self.lane,
                    packet_count: 0,
                },
                self.queued_packets(),
            ));
        }
        match self
            .queued_packets
            .fetch_update(Relaxed, Relaxed, |current| {
                current
                    .checked_add(packet_count)
                    .filter(|next| *next <= self.capacity)
            }) {
            Ok(previous) => Ok((
                LaneCreditReservation {
                    lane: self.lane,
                    packet_count,
                },
                previous,
            )),
            Err(_) => Err(self.pressure_drop(packet_count, byte_count)),
        }
    }

    pub(crate) fn reserve_prefix(&self, requested: usize) -> Option<LaneCreditReservation> {
        if requested == 0 {
            return None;
        }

        let mut current = self.queued_packets.load(Relaxed);
        loop {
            let available = self.capacity.saturating_sub(current);
            let granted = requested.min(available);
            if granted == 0 {
                return None;
            }
            match self.queued_packets.compare_exchange_weak(
                current,
                current + granted,
                Relaxed,
                Relaxed,
            ) {
                Ok(_) => {
                    return Some(LaneCreditReservation {
                        lane: self.lane,
                        packet_count: granted,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    pub(crate) fn release(&self, reservation: LaneCreditReservation) {
        debug_assert_eq!(reservation.lane, self.lane);
        self.release_count(reservation.packet_count);
    }

    pub(crate) fn release_count(&self, count: usize) {
        if count == 0 {
            return;
        }

        let previous = self.queued_packets.fetch_sub(count, Relaxed);
        debug_assert!(
            previous >= count,
            "packet mover lane credit accounting underflow"
        );
    }

    pub(crate) fn pressure_drop(&self, packet_count: usize, byte_count: usize) -> AdmissionDrop {
        AdmissionDrop::pressure(self.lane, packet_count, byte_count)
    }

    pub(crate) fn queued_packets(&self) -> usize {
        self.queued_packets.load(Relaxed)
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QueuedPacket<T> {
    pub(crate) item: T,
    pub(crate) lane: PacketLane,
    pub(crate) packet_count: usize,
    pub(crate) byte_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum QueueAdmission<T> {
    Enqueued,
    Dropped { item: T, drop: AdmissionDrop },
}

#[derive(Debug)]
pub(crate) struct BoundedLaneQueues<T> {
    caps: QueueCaps,
    priority_packets: usize,
    bulk_packets: usize,
    priority: VecDeque<QueuedPacket<T>>,
    bulk: VecDeque<QueuedPacket<T>>,
}

impl<T> BoundedLaneQueues<T> {
    pub(crate) fn new(caps: QueueCaps) -> Self {
        Self {
            caps,
            priority_packets: 0,
            bulk_packets: 0,
            priority: VecDeque::new(),
            bulk: VecDeque::new(),
        }
    }

    pub(crate) fn push(
        &mut self,
        item: T,
        lane: PacketLane,
        packet_count: usize,
        byte_count: usize,
    ) -> QueueAdmission<T> {
        let packet_count = packet_count.max(1);
        let (queued, cap, reason) = match lane {
            PacketLane::Priority => (
                &mut self.priority_packets,
                self.caps.priority_packets,
                AdmissionDropReason::PriorityPressure,
            ),
            PacketLane::Bulk => (
                &mut self.bulk_packets,
                self.caps.bulk_packets,
                AdmissionDropReason::BulkPressure,
            ),
        };
        if queued.saturating_add(packet_count) > cap {
            return QueueAdmission::Dropped {
                item,
                drop: AdmissionDrop {
                    reason,
                    lane,
                    packet_count,
                    byte_count,
                },
            };
        }

        *queued += packet_count;
        let queued_packet = QueuedPacket {
            item,
            lane,
            packet_count,
            byte_count,
        };
        match lane {
            PacketLane::Priority => self.priority.push_back(queued_packet),
            PacketLane::Bulk => self.bulk.push_back(queued_packet),
        }
        QueueAdmission::Enqueued
    }

    pub(crate) fn pop(&mut self) -> Option<QueuedPacket<T>> {
        let packet = self
            .priority
            .pop_front()
            .or_else(|| self.bulk.pop_front())?;
        match packet.lane {
            PacketLane::Priority => {
                self.priority_packets = self.priority_packets.saturating_sub(packet.packet_count);
            }
            PacketLane::Bulk => {
                self.bulk_packets = self.bulk_packets.saturating_sub(packet.packet_count);
            }
        }
        Some(packet)
    }

    pub(crate) fn queued_packets(&self, lane: PacketLane) -> usize {
        match lane {
            PacketLane::Priority => self.priority_packets,
            PacketLane::Bulk => self.bulk_packets,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DispatchBatcher<K, T> {
    key: Option<K>,
    items: Vec<T>,
    buffer_capacity: usize,
}

impl<K: Copy + Eq, T> DispatchBatcher<K, T> {
    pub(crate) fn new(buffer_capacity: usize) -> Self {
        Self {
            key: None,
            items: Vec::with_capacity(buffer_capacity),
            buffer_capacity,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.key.is_none() && self.items.is_empty()
    }

    pub(crate) fn push(
        &mut self,
        key: K,
        batch_max: usize,
        item: T,
        mut dispatch: impl FnMut(K, Vec<T>) -> Vec<T>,
    ) -> Vec<T> {
        let mut returned = Vec::new();
        let batch_max = batch_max.max(1);
        if self.key != Some(key) || self.items.len() >= batch_max {
            returned.extend(self.flush_with(&mut dispatch));
        }

        self.key = Some(key);
        self.items.push(item);

        if self.items.len() >= batch_max {
            returned.extend(self.flush_with(&mut dispatch));
        }
        returned
    }

    pub(crate) fn push_batch(
        &mut self,
        key: K,
        batch_max: usize,
        items: Vec<T>,
        mut dispatch: impl FnMut(K, Vec<T>) -> Vec<T>,
    ) -> Vec<T> {
        if items.is_empty() {
            return Vec::new();
        }

        let mut returned = Vec::new();
        let batch_max = batch_max.max(1);
        if self.key != Some(key) || self.items.len().saturating_add(items.len()) > batch_max {
            returned.extend(self.flush_with(&mut dispatch));
        }

        self.key = Some(key);
        if self.items.is_empty() && items.len() >= batch_max {
            self.items = items;
            returned.extend(self.flush_with(&mut dispatch));
            return returned;
        }

        self.items.extend(items);
        if self.items.len() >= batch_max {
            returned.extend(self.flush_with(&mut dispatch));
        }
        returned
    }

    pub(crate) fn flush(&mut self, mut dispatch: impl FnMut(K, Vec<T>) -> Vec<T>) -> Vec<T> {
        self.flush_with(&mut dispatch)
    }

    fn flush_with(&mut self, dispatch: &mut impl FnMut(K, Vec<T>) -> Vec<T>) -> Vec<T> {
        let Some(key) = self.key.take() else {
            return Vec::new();
        };
        if self.items.is_empty() {
            return Vec::new();
        }

        let items = std::mem::replace(&mut self.items, Vec::with_capacity(self.buffer_capacity));
        dispatch(key, items)
    }
}

pub(crate) struct PriorityBulkDrainCursor<T> {
    first_priority: Option<T>,
    first_bulk: Option<T>,
    remaining: usize,
    drained: usize,
}

impl<T> PriorityBulkDrainCursor<T> {
    pub(crate) fn new(first_priority: Option<T>, first_bulk: Option<T>, budget: usize) -> Self {
        Self {
            first_priority,
            first_bulk,
            remaining: budget,
            drained: 0,
        }
    }

    pub(crate) fn next(
        &mut self,
        priority_rx: &mut Receiver<T>,
        bulk_rx: &mut Receiver<T>,
    ) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let item = if let Some(item) = self.first_priority.take() {
            Some(item)
        } else {
            priority_rx
                .try_recv()
                .ok()
                .or_else(|| self.first_bulk.take())
                .or_else(|| bulk_rx.try_recv().ok())
        }?;

        self.remaining -= 1;
        self.drained += 1;
        Some(item)
    }

    pub(crate) fn next_bulk_if_no_priority(
        &mut self,
        priority_rx: &mut Receiver<T>,
        bulk_rx: &mut Receiver<T>,
    ) -> Option<T> {
        if self.remaining == 0 || self.first_priority.is_some() || !priority_rx.is_empty() {
            return None;
        }

        let item = self.first_bulk.take().or_else(|| bulk_rx.try_recv().ok())?;
        self.remaining -= 1;
        self.drained += 1;
        Some(item)
    }

    pub(crate) fn defer_bulk(&mut self, item: T) {
        debug_assert!(
            self.first_bulk.is_none(),
            "priority/bulk drain already has a deferred bulk item"
        );
        self.first_bulk = Some(item);
        self.remaining = self.remaining.saturating_add(1);
        self.drained = self.drained.saturating_sub(1);
    }

    pub(crate) fn drained(&self) -> usize {
        self.drained
    }

    pub(crate) fn charge_extra(&mut self, extra: usize) {
        self.remaining = self.remaining.saturating_sub(extra);
        self.drained = self.drained.saturating_add(extra);
    }
}

pub(crate) struct SingleLaneDrainCursor<T> {
    first_item: Option<T>,
    remaining: usize,
    drained: usize,
}

impl<T> SingleLaneDrainCursor<T> {
    pub(crate) fn new(first_item: Option<T>, budget: usize) -> Self {
        Self {
            first_item,
            remaining: budget,
            drained: 0,
        }
    }

    pub(crate) fn next(&mut self, rx: &mut Receiver<T>) -> Option<T> {
        if self.remaining == 0 {
            return None;
        }

        let packet = self.first_item.take().or_else(|| rx.try_recv().ok())?;
        self.remaining -= 1;
        self.drained += 1;
        Some(packet)
    }

    pub(crate) fn drained(&self) -> usize {
        self.drained
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_queue_drains_before_bulk() {
        let mut queues = BoundedLaneQueues::new(QueueCaps::new(2, 2));
        assert_eq!(
            queues.push("bulk", PacketLane::Bulk, 1, 100),
            QueueAdmission::Enqueued
        );
        assert_eq!(
            queues.push("priority", PacketLane::Priority, 1, 20),
            QueueAdmission::Enqueued
        );

        assert_eq!(queues.pop().expect("priority").item, "priority");
        assert_eq!(queues.pop().expect("bulk").item, "bulk");
        assert!(queues.pop().is_none());
    }

    #[test]
    fn bulk_pressure_is_explicit_and_attributable() {
        let mut queues = BoundedLaneQueues::new(QueueCaps::new(1, 1));
        assert_eq!(
            queues.push("bulk-1", PacketLane::Bulk, 1, 100),
            QueueAdmission::Enqueued
        );

        let QueueAdmission::Dropped { item, drop } =
            queues.push("bulk-2", PacketLane::Bulk, 1, 200)
        else {
            panic!("second bulk packet must drop under bulk pressure");
        };

        assert_eq!(item, "bulk-2");
        assert_eq!(drop.reason, AdmissionDropReason::BulkPressure);
        assert_eq!(drop.lane, PacketLane::Bulk);
        assert_eq!(drop.packet_count, 1);
        assert_eq!(drop.byte_count, 200);
        assert_eq!(queues.queued_packets(PacketLane::Bulk), 1);
    }

    #[test]
    fn lane_credit_gate_reports_pressure_without_expanding_queue() {
        let gate = LaneCreditGate::new(PacketLane::Bulk, 1);

        let reservation = gate.reserve(1, 100).expect("first packet");
        let drop = gate.reserve(1, 200).expect_err("bulk lane should be full");

        assert_eq!(drop.reason, AdmissionDropReason::BulkPressure);
        assert_eq!(drop.lane, PacketLane::Bulk);
        assert_eq!(drop.packet_count, 1);
        assert_eq!(drop.byte_count, 200);
        assert_eq!(gate.queued_packets(), 1);

        gate.release(reservation);
        assert_eq!(gate.queued_packets(), 0);
    }

    #[test]
    fn lane_credit_gate_can_reserve_prefix_and_release_exact_count() {
        let gate = LaneCreditGate::new(PacketLane::Priority, 3);
        let existing = gate.reserve(1, 10).expect("existing packet");

        let prefix = gate.reserve_prefix(4).expect("partial prefix");

        assert_eq!(prefix.lane(), PacketLane::Priority);
        assert_eq!(prefix.packet_count(), 2);
        assert_eq!(gate.queued_packets(), 3);
        assert!(gate.reserve_prefix(1).is_none());

        gate.release(prefix);
        assert_eq!(gate.queued_packets(), 1);
        gate.release(existing);
        assert_eq!(gate.queued_packets(), 0);
    }

    #[test]
    fn lane_credit_gate_reports_previous_depth_for_backlog_edges() {
        let gate = LaneCreditGate::new(PacketLane::Bulk, 4);

        let (first, previous) = gate.reserve_with_previous(2, 200).expect("first");
        assert_eq!(previous, 0);
        assert_eq!(gate.queued_packets(), 2);

        let (second, previous) = gate.reserve_with_previous(2, 200).expect("second");
        assert_eq!(previous, 2);
        assert_eq!(gate.queued_packets(), 4);
        assert!(gate.reserve_with_previous(1, 100).is_err());

        gate.release(first);
        gate.release(second);
        assert_eq!(gate.queued_packets(), 0);
    }

    #[test]
    fn lane_credit_gate_zero_count_reservation_does_not_consume_capacity() {
        let gate = LaneCreditGate::new(PacketLane::Bulk, 1);

        let (reservation, previous) = gate.reserve_with_previous(0, 0).expect("zero");

        assert_eq!(previous, 0);
        assert_eq!(reservation.packet_count(), 0);
        assert_eq!(gate.queued_packets(), 0);
    }

    #[test]
    fn dispatch_batcher_groups_same_key_until_capacity() {
        let mut batcher = DispatchBatcher::new(4);
        let mut dispatched = Vec::new();

        assert!(
            batcher
                .push(1, 3, "a", |key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );
        assert!(
            batcher
                .push(1, 3, "b", |key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );
        assert!(dispatched.is_empty());

        assert!(
            batcher
                .push(1, 3, "c", |key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );

        assert_eq!(dispatched, vec![(1, vec!["a", "b", "c"])]);
        assert!(batcher.is_empty());
    }

    #[test]
    fn dispatch_batcher_flushes_on_key_change_and_preserves_returned_items() {
        let mut batcher = DispatchBatcher::new(4);
        assert!(
            batcher
                .push(1, 8, "a", |_key, _items| Vec::new())
                .is_empty()
        );

        let returned = batcher.push(2, 8, "b", |key, items| {
            assert_eq!(key, 1);
            assert_eq!(items, vec!["a"]);
            vec!["returned"]
        });

        assert_eq!(returned, vec!["returned"]);
        let mut dispatched = Vec::new();
        assert!(
            batcher
                .flush(|key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );
        assert_eq!(dispatched, vec![(2, vec!["b"])]);
    }

    #[test]
    fn dispatch_batcher_directly_flushes_full_batch_when_empty() {
        let mut batcher = DispatchBatcher::new(4);
        let mut dispatched = Vec::new();

        assert!(
            batcher
                .push_batch(7, 2, vec!["a", "b"], |key, items| {
                    dispatched.push((key, items));
                    Vec::new()
                })
                .is_empty()
        );

        assert_eq!(dispatched, vec![(7, vec!["a", "b"])]);
        assert!(batcher.is_empty());
    }

    #[tokio::test]
    async fn priority_bulk_drain_prefers_ready_priority_over_selected_bulk() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("priority").await.unwrap();
        bulk_tx.send("bulk-queued").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("bulk-selected"), 4);

        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), Some("priority"));
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("bulk-selected")
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("bulk-queued")
        );
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
        assert_eq!(drain.drained(), 3);
    }

    #[tokio::test]
    async fn priority_bulk_drain_charges_batch_extra_against_budget() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("queued-priority").await.unwrap();
        bulk_tx.send("queued-bulk").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("selected-bulk"), 4);

        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("queued-priority")
        );
        drain.charge_extra(3);
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
        assert_eq!(bulk_rx.try_recv().ok(), Some("queued-bulk"));
        assert_eq!(drain.drained(), 4);
    }

    #[tokio::test]
    async fn priority_bulk_drain_bulk_only_stops_for_priority() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

        priority_tx.send("priority").await.unwrap();
        bulk_tx.send("bulk").await.unwrap();
        let mut drain = PriorityBulkDrainCursor::new(None, Some("selected-bulk"), 4);

        assert_eq!(
            drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
            None,
            "bulk coalescing must stop when priority work is ready"
        );
        assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), Some("priority"));
        assert_eq!(
            drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
            Some("selected-bulk")
        );
        assert_eq!(
            drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
            Some("bulk")
        );
    }

    #[tokio::test]
    async fn priority_bulk_drain_deferred_bulk_yields_to_later_priority() {
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (_bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);
        let mut drain = PriorityBulkDrainCursor::new(None, None, 4);

        drain.defer_bulk("deferred-bulk");
        priority_tx.send("priority").await.unwrap();

        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("priority"),
            "a non-coalesced bulk command should be put back behind new priority work"
        );
        assert_eq!(
            drain.next(&mut priority_rx, &mut bulk_rx),
            Some("deferred-bulk")
        );
    }

    #[tokio::test]
    async fn single_lane_drain_owns_first_item_and_budget() {
        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(4);

        tun_tx.send("queued-1").await.unwrap();
        tun_tx.send("queued-2").await.unwrap();
        tun_tx.send("queued-3").await.unwrap();
        let mut drain = SingleLaneDrainCursor::new(Some("selected"), 3);

        assert_eq!(drain.next(&mut tun_rx), Some("selected"));
        assert_eq!(drain.next(&mut tun_rx), Some("queued-1"));
        assert_eq!(drain.next(&mut tun_rx), Some("queued-2"));
        assert_eq!(drain.next(&mut tun_rx), None);
        assert_eq!(tun_rx.try_recv().ok(), Some("queued-3"));
        assert_eq!(drain.drained(), 3);
    }
}
