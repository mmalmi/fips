use super::{AdmissionDrop, AdmissionDropReason, PacketLane};
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::Relaxed},
};

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
}
