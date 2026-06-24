use super::LaneCreditReservation;
use crate::transport::{TransportAddr, TransportId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketLane {
    Priority,
    Bulk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionClass {
    Control,
    Rekey,
    Mmp,
    Liveness,
    InteractiveData,
    BulkData,
}

impl AdmissionClass {
    pub(crate) fn lane(self) -> PacketLane {
        match self {
            Self::Control | Self::Rekey | Self::Mmp | Self::Liveness | Self::InteractiveData => {
                PacketLane::Priority
            }
            Self::BulkData => PacketLane::Bulk,
        }
    }

    pub(crate) fn reserves_progress(self) -> bool {
        !matches!(self, Self::BulkData)
    }
}

pub(crate) fn classify_udp_admission(
    packet_len: usize,
    priority_packet_max_len: usize,
) -> AdmissionClass {
    if packet_len <= priority_packet_max_len {
        AdmissionClass::InteractiveData
    } else {
        AdmissionClass::BulkData
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketFacts {
    pub(crate) transport_id: TransportId,
    pub(crate) remote_addr: TransportAddr,
    pub(crate) packet_len: usize,
    pub(crate) received_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpIngress<P> {
    pub(crate) packet: P,
    pub(crate) facts: PacketFacts,
}

impl<P> UdpIngress<P> {
    pub(crate) fn new(packet: P, facts: PacketFacts) -> Self {
        Self { packet, facts }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedPacket<P> {
    pub(crate) packet: P,
    pub(crate) facts: PacketFacts,
    pub(crate) class: AdmissionClass,
    pub(crate) lane: PacketLane,
    pub(crate) credit: AdmissionCredit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionCredit {
    lane: PacketLane,
    reservation: LaneCreditReservation,
}

impl AdmissionCredit {
    pub(crate) fn new(lane: PacketLane, reservation: LaneCreditReservation) -> Self {
        debug_assert_eq!(lane, reservation.lane());
        Self { lane, reservation }
    }

    pub(crate) fn lane(self) -> PacketLane {
        self.lane
    }

    pub(crate) fn packet_count(self) -> usize {
        self.reservation.packet_count()
    }

    pub(crate) fn into_lane_reservation(self) -> LaneCreditReservation {
        self.reservation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionPrefix {
    lane: PacketLane,
    requested_packets: usize,
    requested_bytes: usize,
    credit: AdmissionCredit,
}

impl AdmissionPrefix {
    pub(crate) fn new(
        lane: PacketLane,
        requested_packets: usize,
        requested_bytes: usize,
        reservation: LaneCreditReservation,
    ) -> Self {
        Self {
            lane,
            requested_packets,
            requested_bytes,
            credit: AdmissionCredit::new(lane, reservation),
        }
    }

    pub(crate) fn lane(self) -> PacketLane {
        self.lane
    }

    pub(crate) fn requested_packets(self) -> usize {
        self.requested_packets
    }

    pub(crate) fn requested_bytes(self) -> usize {
        self.requested_bytes
    }

    pub(crate) fn packet_count(self) -> usize {
        self.credit.packet_count()
    }

    pub(crate) fn into_lane_reservation(self) -> LaneCreditReservation {
        self.credit.into_lane_reservation()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDropReason {
    PriorityPressure,
    BulkPressure,
    Malformed,
    ReceiverClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionDrop {
    pub(crate) reason: AdmissionDropReason,
    pub(crate) lane: PacketLane,
    pub(crate) packet_count: usize,
    pub(crate) byte_count: usize,
}

impl AdmissionDrop {
    pub(crate) fn pressure(lane: PacketLane, packet_count: usize, byte_count: usize) -> Self {
        let reason = match lane {
            PacketLane::Priority => AdmissionDropReason::PriorityPressure,
            PacketLane::Bulk => AdmissionDropReason::BulkPressure,
        };
        Self {
            reason,
            lane,
            packet_count,
            byte_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDecision<P> {
    Admit(AdmittedPacket<P>),
    Drop(AdmissionDrop),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionPrefixDecision {
    Admit(AdmissionPrefix),
    Drop(AdmissionDrop),
}

pub(crate) trait UdpAdmission<P> {
    fn admit_udp(&self, packet: UdpIngress<P>, class: AdmissionClass) -> AdmissionDecision<P>;
}

pub(crate) trait UdpBatchAdmission {
    fn reserve_udp_prefix(
        &self,
        lane: PacketLane,
        packet_count: usize,
        byte_count: usize,
    ) -> AdmissionPrefixDecision;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_classes_reserve_progress_for_non_bulk_work() {
        for class in [
            AdmissionClass::Control,
            AdmissionClass::Rekey,
            AdmissionClass::Mmp,
            AdmissionClass::Liveness,
            AdmissionClass::InteractiveData,
        ] {
            assert_eq!(class.lane(), PacketLane::Priority);
            assert!(class.reserves_progress());
        }

        assert_eq!(AdmissionClass::BulkData.lane(), PacketLane::Bulk);
        assert!(!AdmissionClass::BulkData.reserves_progress());
    }

    #[test]
    fn udp_size_classifier_maps_small_packets_to_reserved_progress() {
        assert_eq!(
            classify_udp_admission(512, 512),
            AdmissionClass::InteractiveData
        );
        assert_eq!(classify_udp_admission(513, 512), AdmissionClass::BulkData);
    }

    #[test]
    fn admission_credit_wraps_lane_reservation() {
        let gate = super::super::LaneCreditGate::new(PacketLane::Priority, 2);
        let reservation = gate.reserve(1, 64).expect("credit");
        let credit = AdmissionCredit::new(PacketLane::Priority, reservation);

        assert_eq!(credit.lane(), PacketLane::Priority);
        assert_eq!(credit.packet_count(), 1);

        gate.release(credit.into_lane_reservation());
        assert_eq!(gate.queued_packets(), 0);
    }
}
