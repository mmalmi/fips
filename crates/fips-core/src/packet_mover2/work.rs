#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoWork {
    reservation: OwnerReservation,
    packet: SocketPacket,
}

impl CryptoWork {
    #[cfg(test)]
    fn order(&self) -> u64 {
        self.reservation.order.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundCryptoWork {
    reservation: OwnerReservation,
    packet: OutboundPacket,
}

impl OutboundCryptoWork {
    #[cfg(test)]
    fn order(&self) -> u64 {
        self.reservation.order.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoCompletion {
    reservation: OwnerReservation,
    result: CryptoResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CryptoResult {
    Opened(PacketOutput),
    Sealed(PacketOutput),
    Outbound(OutboundPacket),
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketOutput {
    owner: OwnerId,
    counter: u64,
    ingress_seq: u64,
    target: OutputTarget,
    path: Option<TransportPath>,
    payload: PacketBuffer,
}

impl PacketOutput {
    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) fn ingress_seq(&self) -> u64 {
        self.ingress_seq
    }

    pub(crate) fn target(&self) -> OutputTarget {
        self.target
    }

    pub(crate) fn path(&self) -> Option<TransportPath> {
        self.path.clone()
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub(crate) fn into_payload(self) -> PacketBuffer {
        self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetiredPacket {
    Output(PacketOutput),
    Outbound(OutboundPacket),
    Drop(PacketDrop),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketDropReason {
    Admission(AdmissionDropReason),
    UnknownOwner,
    Replay,
    OwnerInFlightFull,
    StaleGeneration,
    StaleCompletionGeneration,
    CryptoFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketDrop {
    owner: OwnerId,
    counter: Option<u64>,
    ingress_seq: Option<u64>,
    lane: Lane,
    reason: PacketDropReason,
}

impl PacketDrop {
    fn from_queued(queued: &QueuedPacket, reason: PacketDropReason) -> Self {
        Self {
            owner: queued.packet.owner,
            counter: Some(queued.packet.counter),
            ingress_seq: Some(queued.ingress_seq),
            lane: queued.packet.lane(),
            reason,
        }
    }

    fn from_queued_outbound(queued: &QueuedOutboundPacket, reason: PacketDropReason) -> Self {
        Self {
            owner: queued.packet.owner,
            counter: None,
            ingress_seq: Some(queued.ingress_seq),
            lane: queued.packet.lane(),
            reason,
        }
    }

    fn from_completion(completion: &CryptoCompletion, reason: PacketDropReason) -> Self {
        Self {
            owner: completion.reservation.owner,
            counter: Some(completion.reservation.counter),
            ingress_seq: Some(completion.reservation.ingress_seq),
            lane: completion.reservation.lane,
            reason,
        }
    }

    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(&self) -> Option<u64> {
        self.counter
    }

    pub(crate) fn ingress_seq(&self) -> Option<u64> {
        self.ingress_seq
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn reason(&self) -> PacketDropReason {
        self.reason
    }
}

impl From<AdmissionDrop> for PacketDrop {
    fn from(drop: AdmissionDrop) -> Self {
        Self {
            owner: drop.owner,
            counter: Some(drop.counter),
            ingress_seq: None,
            lane: drop.lane,
            reason: PacketDropReason::Admission(drop.reason),
        }
    }
}

impl From<OutboundAdmissionDrop> for PacketDrop {
    fn from(drop: OutboundAdmissionDrop) -> Self {
        Self {
            owner: drop.owner,
            counter: None,
            ingress_seq: None,
            lane: drop.lane,
            reason: PacketDropReason::Admission(drop.reason),
        }
    }
}

impl From<OwnerReserveError> for PacketDropReason {
    fn from(error: OwnerReserveError) -> Self {
        match error {
            OwnerReserveError::Replay => Self::Replay,
            OwnerReserveError::InFlightFull => Self::OwnerInFlightFull,
            OwnerReserveError::StaleGeneration => Self::StaleGeneration,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AdmissionBatchSummary {
    admitted: usize,
    dropped: usize,
}

impl AdmissionBatchSummary {
    pub(crate) fn admitted(self) -> usize {
        self.admitted
    }

    pub(crate) fn dropped(self) -> usize {
        self.dropped
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PacketMoverTurn {
    dispatched: usize,
    retired: Vec<RetiredPacket>,
    drops: Vec<PacketDrop>,
}

impl PacketMoverTurn {
    pub(crate) fn dispatched(&self) -> usize {
        self.dispatched
    }

    pub(crate) fn retired(&self) -> &[RetiredPacket] {
        &self.retired
    }

    pub(crate) fn drops(&self) -> &[PacketDrop] {
        &self.drops
    }

    #[cfg(test)]
    fn outputs(&self) -> Vec<&PacketOutput> {
        self.retired
            .iter()
            .filter_map(|item| match item {
                RetiredPacket::Output(output) => Some(output),
                RetiredPacket::Outbound(_) => None,
                RetiredPacket::Drop(_) => None,
            })
            .collect()
    }
}
