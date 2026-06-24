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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedPacket<P> {
    pub(crate) packet: P,
    pub(crate) facts: PacketFacts,
    pub(crate) class: AdmissionClass,
    pub(crate) lane: PacketLane,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDecision<P> {
    Admit(AdmittedPacket<P>),
    Drop(AdmissionDrop),
}

pub(crate) trait UdpAdmission<P> {
    fn admit_udp(&mut self, packet: UdpIngress<P>, class: AdmissionClass) -> AdmissionDecision<P>;
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
}
