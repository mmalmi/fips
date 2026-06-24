use super::{AdmissionDrop, AdmissionDropReason, PacketLane};
use std::collections::VecDeque;

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
}
