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
    Outbound(WrappedOutboundPacket),
    Failed(CryptoFailureKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CryptoFailureKind {
    Open,
    Seal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketOutput {
    owner: OwnerId,
    counter: u64,
    ingress_seq: u64,
    lane: Lane,
    target: OutputTarget,
    source_path: Option<TransportPath>,
    previous_hop: Option<NodeAddr>,
    ce_flag: bool,
    path: Option<TransportPath>,
    activity_tick: Option<ActivityTick>,
    fmp_timestamp_ms: Option<u32>,
    source_wire_len: Option<usize>,
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

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn target(&self) -> OutputTarget {
        self.target
    }

    pub(crate) fn path(&self) -> Option<TransportPath> {
        self.path.clone()
    }

    pub(crate) fn source_path(&self) -> Option<&TransportPath> {
        self.source_path.as_ref()
    }

    pub(crate) fn take_source_path(&mut self) -> Option<TransportPath> {
        self.source_path.take()
    }

    pub(crate) fn restore_source_path(&mut self, path: TransportPath) {
        self.source_path = Some(path);
    }

    pub(crate) fn previous_hop(&self) -> Option<NodeAddr> {
        self.previous_hop
    }

    pub(crate) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub(crate) fn source_wire_len(&self) -> Option<usize> {
        self.source_wire_len
    }

    pub(crate) fn fmp_timestamp_ms(&self) -> Option<u32> {
        self.fmp_timestamp_ms
    }

    pub(crate) fn into_payload(self) -> PacketBuffer {
        self.payload
    }

    fn promote_opened_latency_sensitive_payload(&mut self) {
        if self.lane == Lane::Priority
            || !matches!(self.target, OutputTarget::Tun | OutputTarget::Endpoint)
        {
            return;
        }
        if self
            .opened_payload()
            .is_some_and(crate::node::endpoint_payload_is_latency_sensitive)
        {
            self.lane = Lane::Priority;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2WrappedOutboundReceipt {
    owner: OwnerId,
    counter: u64,
}

impl PacketMover2WrappedOutboundReceipt {
    pub(crate) fn owner(self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(self) -> u64 {
        self.counter
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WrappedOutboundPacket {
    packet: OutboundPacket,
    receipt: PacketMover2WrappedOutboundReceipt,
}

impl WrappedOutboundPacket {
    pub(crate) fn new(packet: OutboundPacket, owner: OwnerId, counter: u64) -> Self {
        Self {
            packet,
            receipt: PacketMover2WrappedOutboundReceipt { owner, counter },
        }
    }

    pub(crate) fn receipt(&self) -> PacketMover2WrappedOutboundReceipt {
        self.receipt
    }

    pub(crate) fn into_packet(self) -> OutboundPacket {
        self.packet
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetiredPacket {
    Output(PacketOutput),
    Outbound(WrappedOutboundPacket),
    Drop(PacketDrop),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketDropReason {
    Admission(AdmissionDropReason),
    UnknownOwner,
    Replay,
    OwnerInFlightFull,
    StaleGeneration,
    CounterExhausted,
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
    crypto_failure: Option<CryptoFailureKind>,
    wire_flags: Option<u8>,
    authenticated_counter_highest: Option<u64>,
}

impl PacketDrop {
    fn from_queued(queued: &QueuedPacket, reason: PacketDropReason) -> Self {
        Self {
            owner: queued.packet.owner,
            counter: Some(queued.packet.counter),
            ingress_seq: Some(queued.ingress_seq),
            lane: queued.packet.lane(),
            reason,
            crypto_failure: None,
            wire_flags: Some(queued.packet.wire_flags),
            authenticated_counter_highest: None,
        }
    }

    fn from_queued_outbound(queued: &QueuedOutboundPacket, reason: PacketDropReason) -> Self {
        Self {
            owner: queued.packet.owner,
            counter: None,
            ingress_seq: Some(queued.ingress_seq),
            lane: queued.packet.lane(),
            reason,
            crypto_failure: None,
            wire_flags: None,
            authenticated_counter_highest: None,
        }
    }

    fn from_completion(
        completion: &CryptoCompletion,
        reason: PacketDropReason,
        crypto_failure: Option<CryptoFailureKind>,
    ) -> Self {
        Self {
            owner: completion.reservation.owner,
            counter: Some(completion.reservation.counter),
            ingress_seq: Some(completion.reservation.ingress_seq),
            lane: completion.reservation.lane,
            reason,
            crypto_failure,
            wire_flags: Some(completion.reservation.wire_flags),
            authenticated_counter_highest: None,
        }
    }

    fn from_completion_with_authenticated_highest(
        completion: &CryptoCompletion,
        reason: PacketDropReason,
        crypto_failure: CryptoFailureKind,
        authenticated_counter_highest: u64,
    ) -> Self {
        let mut drop = Self::from_completion(completion, reason, Some(crypto_failure));
        drop.authenticated_counter_highest = Some(authenticated_counter_highest);
        drop
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

    pub(crate) fn crypto_failure(&self) -> Option<CryptoFailureKind> {
        self.crypto_failure
    }

    pub(crate) fn wire_flags(&self) -> Option<u8> {
        self.wire_flags
    }

    pub(crate) fn authenticated_counter_highest(&self) -> Option<u64> {
        self.authenticated_counter_highest
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
            crypto_failure: None,
            wire_flags: None,
            authenticated_counter_highest: None,
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
            crypto_failure: None,
            wire_flags: None,
            authenticated_counter_highest: None,
        }
    }
}

impl From<OwnerReserveError> for PacketDropReason {
    fn from(error: OwnerReserveError) -> Self {
        match error {
            OwnerReserveError::Replay => Self::Replay,
            OwnerReserveError::InFlightFull => Self::OwnerInFlightFull,
            OwnerReserveError::StaleGeneration => Self::StaleGeneration,
            OwnerReserveError::CounterExhausted => Self::CounterExhausted,
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
