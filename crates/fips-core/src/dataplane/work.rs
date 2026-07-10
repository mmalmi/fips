#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoWork {
    reservation: OwnerReservation,
    packet: SocketPacket,
}

impl CryptoWork {
    fn is_open_fsp_session_payload(&self) -> bool {
        self.reservation.owner.protocol() == PacketProtocol::Fsp
            && matches!(self.packet.output, OutputTarget::SessionPayload { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundCryptoWork {
    reservation: OwnerReservation,
    packet: OutboundPacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoCompletion {
    reservation: OwnerReservation,
    result: CryptoResult,
}

#[derive(Debug)]
struct CryptoOwnerRun {
    next_order: OrderToken,
    open_fsp_session_payload: bool,
    items: Vec<CryptoOwnerRunItem>,
}

#[derive(Debug)]
// Inline states keep the 128-packet run in one allocation without per-packet boxes.
struct CryptoOwnerRunItem {
    reservation: OwnerReservation,
    state: CryptoOwnerRunItemState,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum CryptoOwnerRunItemState {
    Open(SocketPacket),
    Seal(OutboundPacket),
    Completed(CryptoResult),
}

impl CryptoOwnerRun {
    fn new(work: CryptoOwnerRunItem, capacity: usize) -> Self {
        let mut items = Vec::with_capacity(capacity);
        let next_order = work.reservation.order.next();
        let open_fsp_session_payload = work.is_open_fsp_session_payload();
        items.push(work);
        Self {
            next_order,
            open_fsp_session_payload,
            items,
        }
    }

    fn matches(
        &self,
        reservation: &OwnerReservation,
        is_open: bool,
        open_fsp_session_payload: bool,
    ) -> bool {
        let Some(first) = self.first_reservation() else {
            return false;
        };
        first.owner_shard() == reservation.owner_shard()
            && first.owner == reservation.owner
            && first.generation == reservation.generation
            && first.lane == reservation.lane
            && self.next_order == reservation.order
            && self.is_open() == is_open
            && (!is_open || first.source_path == reservation.source_path)
            && self.open_fsp_session_payload == open_fsp_session_payload
    }

    fn push(&mut self, work: CryptoOwnerRunItem) {
        assert!(
            self.matches(
                &work.reservation,
                work.is_open(),
                work.is_open_fsp_session_payload(),
            ),
            "crypto owner run must be contiguous"
        );
        self.next_order = work.reservation.order.next();
        self.items.push(work);
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn first_order(&self) -> Option<OrderToken> {
        self.items.first().map(|item| item.reservation.order)
    }

    fn first_reservation(&self) -> Option<&OwnerReservation> {
        self.items.first().map(|item| &item.reservation)
    }

    fn bulk_count(&self) -> usize {
        if self
            .first_reservation()
            .is_some_and(|reservation| reservation.lane == Lane::Bulk)
        {
            self.len()
        } else {
            0
        }
    }

    fn is_open_fsp_session_payload_run(&self) -> bool {
        !self.is_empty()
            && self.is_open()
            && self
                .first_reservation()
                .is_some_and(|reservation| reservation.owner.protocol() == PacketProtocol::Fsp)
            && self.open_fsp_session_payload
            && self
                .items
                .iter()
                .all(CryptoOwnerRunItem::is_open_fsp_session_payload)
    }

    fn is_open(&self) -> bool {
        self.items
            .first()
            .is_some_and(CryptoOwnerRunItem::is_open)
    }

    fn split_off(&mut self, at: usize) -> Self {
        Self {
            next_order: self.next_order,
            open_fsp_session_payload: self.open_fsp_session_payload,
            items: self.items.split_off(at),
        }
    }

    fn consume_in_order(self, mut consume: impl FnMut(CryptoCompletion)) {
        for item in self.items {
            consume(item.into_completion());
        }
    }
}

impl CryptoOwnerRunItem {
    fn open(work: CryptoWork) -> Self {
        let CryptoWork {
            reservation,
            packet,
        } = work;
        Self {
            reservation,
            state: CryptoOwnerRunItemState::Open(packet),
        }
    }

    fn seal(work: OutboundCryptoWork) -> Self {
        let OutboundCryptoWork {
            reservation,
            packet,
        } = work;
        Self {
            reservation,
            state: CryptoOwnerRunItemState::Seal(packet),
        }
    }

    fn is_open(&self) -> bool {
        match &self.state {
            CryptoOwnerRunItemState::Open(_) => true,
            CryptoOwnerRunItemState::Seal(_) => false,
            CryptoOwnerRunItemState::Completed(result) => result.is_open_family(),
        }
    }

    fn is_open_fsp_session_payload(&self) -> bool {
        match &self.state {
            CryptoOwnerRunItemState::Open(packet) => {
                self.reservation.owner.protocol() == PacketProtocol::Fsp
                    && matches!(packet.output, OutputTarget::SessionPayload { .. })
            }
            CryptoOwnerRunItemState::Completed(CryptoResult::Opened(output)) => {
                matches!(output.target(), OutputTarget::SessionPayload { .. })
            }
            CryptoOwnerRunItemState::Seal(_) | CryptoOwnerRunItemState::Completed(_) => false,
        }
    }

    fn into_completion(self) -> CryptoCompletion {
        let result = match self.state {
            CryptoOwnerRunItemState::Completed(result) => result,
            CryptoOwnerRunItemState::Open(_) | CryptoOwnerRunItemState::Seal(_) => {
                panic!("crypto owner run retired before completion")
            }
        };
        CryptoCompletion {
            reservation: self.reservation,
            result,
        }
    }
}

#[derive(Debug)]
enum CryptoCompletionRun {
    Completed(Vec<CryptoCompletion>),
    OwnerRun(CryptoOwnerRun),
}

#[derive(Debug)]
pub(crate) struct CryptoCompletionBatch {
    owner_shard: usize,
    owner: OwnerId,
    generation: u64,
    lane: Lane,
    completions: CryptoCompletionRun,
}

impl CryptoCompletion {
    fn is_open_family(&self) -> bool {
        self.result.is_open_family()
    }

    fn same_family(&self, other: &CryptoCompletion) -> bool {
        self.is_open_family() == other.is_open_family()
    }

    fn order(&self) -> OrderToken {
        self.reservation.order
    }
}

impl CryptoResult {
    fn is_open_family(&self) -> bool {
        match self {
            CryptoResult::Opened(_) | CryptoResult::Failed(CryptoFailureKind::Open) => true,
            CryptoResult::Sealed(_)
            | CryptoResult::Outbound(_)
            | CryptoResult::Failed(CryptoFailureKind::Seal) => false,
        }
    }
}

impl CryptoCompletionBatch {
    pub(crate) fn from_completion(completion: CryptoCompletion) -> Self {
        let owner_shard = completion.reservation.owner_shard();
        let owner = completion.reservation.owner;
        let generation = completion.reservation.generation;
        let lane = completion.reservation.lane;
        Self {
            owner_shard,
            owner,
            generation,
            lane,
            completions: CryptoCompletionRun::Completed(vec![completion]),
        }
    }

    fn from_owner_run(run: CryptoOwnerRun) -> Self {
        let reservation = run
            .first_reservation()
            .expect("crypto owner run contains a completion");
        let owner_shard = reservation.owner_shard();
        let owner = reservation.owner;
        let generation = reservation.generation;
        let lane = reservation.lane;
        Self {
            owner_shard,
            owner,
            generation,
            lane,
            completions: CryptoCompletionRun::OwnerRun(run),
        }
    }

    pub(crate) fn push_grouped(
        completion: CryptoCompletion,
        batches: &mut Vec<CryptoCompletionBatch>,
    ) {
        if let Some(last) = batches.last_mut()
            && last.matches(&completion)
        {
            let CryptoCompletionRun::Completed(completions) = &mut last.completions else {
                unreachable!("shared owner runs do not match grouped completions");
            };
            completions.push(completion);
            return;
        }
        batches.push(Self::from_completion(completion));
    }

    #[cfg(test)]
    pub(crate) fn drain_completion_vec_into_batches(
        completions: &mut Vec<CryptoCompletion>,
        batches: &mut Vec<CryptoCompletionBatch>,
    ) -> usize {
        let count = completions.len();
        for completion in completions.drain(..) {
            Self::push_grouped(completion, batches);
        }
        count
    }

    pub(crate) fn len(&self) -> usize {
        match &self.completions {
            CryptoCompletionRun::Completed(completions) => completions.len(),
            CryptoCompletionRun::OwnerRun(run) => run.len(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn first_order(&self) -> Option<OrderToken> {
        match &self.completions {
            CryptoCompletionRun::Completed(completions) => {
                completions.first().map(CryptoCompletion::order)
            }
            CryptoCompletionRun::OwnerRun(run) => run.first_order(),
        }
    }

    pub(crate) fn owner_shard(&self) -> usize {
        self.owner_shard
    }

    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn is_open_fsp_session_payload_run(&self) -> bool {
        if self.is_empty() || self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }
        match &self.completions {
            CryptoCompletionRun::Completed(completions) => completions.iter().all(|completion| {
                matches!(
                    &completion.result,
                    CryptoResult::Opened(output)
                        if matches!(output.target(), OutputTarget::SessionPayload { .. })
                )
            }),
            CryptoCompletionRun::OwnerRun(run) => run.is_open_fsp_session_payload_run(),
        }
    }

    pub(crate) fn split_off(&mut self, at: usize) -> Self {
        let completions = match &mut self.completions {
            CryptoCompletionRun::Completed(completions) => {
                CryptoCompletionRun::Completed(completions.split_off(at))
            }
            CryptoCompletionRun::OwnerRun(run) => {
                CryptoCompletionRun::OwnerRun(run.split_off(at))
            }
        };
        Self {
            owner_shard: self.owner_shard,
            owner: self.owner,
            generation: self.generation,
            lane: self.lane,
            completions,
        }
    }

    pub(crate) fn into_completions(self) -> Vec<CryptoCompletion> {
        let mut completions = Vec::with_capacity(self.len());
        self.consume_in_order(|completion| completions.push(completion));
        completions
    }

    pub(crate) fn consume_in_order(self, mut consume: impl FnMut(CryptoCompletion)) {
        match self.completions {
            CryptoCompletionRun::Completed(completions) => {
                for completion in completions {
                    consume(completion);
                }
            }
            CryptoCompletionRun::OwnerRun(run) => run.consume_in_order(consume),
        }
    }

    fn matches(&self, completion: &CryptoCompletion) -> bool {
        let CryptoCompletionRun::Completed(completions) = &self.completions else {
            return false;
        };
        self.owner_shard == completion.reservation.owner_shard()
            && self.owner == completion.reservation.owner
            && self.generation == completion.reservation.generation
            && self.lane == completion.reservation.lane
            && completions
                .first()
                .is_none_or(|first| first.same_family(completion))
            && completions
                .last()
                .is_none_or(|last| last.order().next() == completion.order())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CryptoResult {
    Opened(PacketOutput),
    Sealed(PacketOutput),
    Outbound(OutboundPacket),
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
    path_mtu: u16,
    source_peer: Option<crate::PeerIdentity>,
    path: Option<TransportPath>,
    activity_tick: Option<ActivityTick>,
    fmp_timestamp_ms: Option<u32>,
    source_wire_len: Option<usize>,
    fsp_send_receipt: Option<DataplaneFspSendReceipt>,
    send_token: Option<u64>,
    payload: PacketBuffer,
}

impl PacketOutput {
    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn target(&self) -> OutputTarget {
        self.target
    }

    pub(crate) fn source_path(&self) -> Option<&TransportPath> {
        self.source_path.as_ref()
    }

    pub(crate) fn previous_hop(&self) -> Option<NodeAddr> {
        self.previous_hop
    }

    pub(crate) fn ce_flag(&self) -> bool {
        self.ce_flag
    }

    pub(crate) fn path_mtu(&self) -> u16 {
        self.path_mtu
    }

    pub(crate) fn source_peer(&self) -> Option<crate::PeerIdentity> {
        self.source_peer
    }

    pub(crate) fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub(crate) fn source_wire_len(&self) -> Option<usize> {
        self.source_wire_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneTransportSentReceipt {
    pub(crate) owner: OwnerId,
    pub(crate) counter: u64,
    pub(crate) fmp_timestamp_ms: Option<u32>,
    pub(crate) payload_len: usize,
    pub(crate) fsp_send_receipt: Option<DataplaneFspSendReceipt>,
    pub(crate) send_token: Option<u64>,
}

impl DataplaneTransportSentReceipt {
    pub(crate) fn from_output(output: &PacketOutput) -> Self {
        Self {
            owner: output.owner,
            counter: output.counter,
            fmp_timestamp_ms: output.fmp_timestamp_ms,
            payload_len: output.payload.len(),
            fsp_send_receipt: output.fsp_send_receipt,
            send_token: output.send_token,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFspSendReceipt {
    pub(crate) owner: OwnerId,
    pub(crate) counter: u64,
}

pub(crate) struct DataplaneRetiredOutputSink<'a> {
    outputs: &'a mut Vec<PacketOutput>,
    outbound_packets: &'a mut Vec<OutboundPacket>,
    fsp_authenticated_ingress: &'a mut DataplaneFspAuthenticatedIngress,
}

impl<'a> DataplaneRetiredOutputSink<'a> {
    pub(crate) fn new(
        outputs: &'a mut Vec<PacketOutput>,
        outbound_packets: &'a mut Vec<OutboundPacket>,
        fsp_authenticated_ingress: &'a mut DataplaneFspAuthenticatedIngress,
    ) -> Self {
        Self {
            outputs,
            outbound_packets,
            fsp_authenticated_ingress,
        }
    }

    pub(crate) fn push_output(&mut self, output: PacketOutput) {
        self.outputs.push(output);
    }

    pub(crate) fn push_outbound(&mut self, packet: OutboundPacket) {
        self.outbound_packets.push(packet);
    }

    pub(crate) fn push_endpoint_data_batch(
        &mut self,
        ingress: DataplaneFspEndpointDataIngress,
    ) {
        self.fsp_authenticated_ingress
            .push_endpoint_data_batch(DataplaneEndpointDataBatch::from_ingress(ingress));
    }

    pub(crate) fn append_endpoint_data_batch(&mut self, batch: DataplaneEndpointDataBatch) {
        self.fsp_authenticated_ingress
            .push_endpoint_data_batch(batch);
    }
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
    send_token: Option<u64>,
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
            send_token: None,
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
            send_token: queued.packet.send_token,
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
            send_token: completion.reservation.send_token,
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

    pub(crate) fn send_token(&self) -> Option<u64> {
        self.send_token
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
            counter: drop.counter,
            send_token: drop.send_token,
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
