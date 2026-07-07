#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoWork {
    reservation: OwnerReservation,
    packet: SocketPacket,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CryptoCompletionSource {
    Open,
    Seal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoCompletionBatch {
    owner_shard: usize,
    owner: OwnerId,
    generation: u64,
    lane: Lane,
    source: CryptoCompletionSource,
    completions: Vec<CryptoCompletion>,
}

impl CryptoCompletion {
    fn source(&self) -> CryptoCompletionSource {
        match &self.result {
            CryptoResult::Opened(_) | CryptoResult::Failed(CryptoFailureKind::Open) => {
                CryptoCompletionSource::Open
            }
            CryptoResult::Sealed(_)
            | CryptoResult::Outbound(_)
            | CryptoResult::Failed(CryptoFailureKind::Seal) => CryptoCompletionSource::Seal,
        }
    }

    fn order(&self) -> OrderToken {
        self.reservation.order
    }
}

impl CryptoCompletionBatch {
    pub(crate) fn from_completion(completion: CryptoCompletion) -> Self {
        let owner_shard = completion.reservation.owner_shard();
        let owner = completion.reservation.owner;
        let generation = completion.reservation.generation;
        let lane = completion.reservation.lane;
        let source = completion.source();
        Self {
            owner_shard,
            owner,
            generation,
            lane,
            source,
            completions: vec![completion],
        }
    }

    pub(crate) fn from_completion_run(completions: Vec<CryptoCompletion>) -> Option<Self> {
        let first = completions.first()?;
        let owner_shard = first.reservation.owner_shard();
        let owner = first.reservation.owner;
        let generation = first.reservation.generation;
        let lane = first.reservation.lane;
        let source = first.source();
        debug_assert!(completion_run_is_contiguous(
            &completions,
            owner_shard,
            owner,
            generation,
            lane,
            source,
        ));
        Some(Self {
            owner_shard,
            owner,
            generation,
            lane,
            source,
            completions,
        })
    }

    pub(crate) fn push_grouped(
        completion: CryptoCompletion,
        batches: &mut Vec<CryptoCompletionBatch>,
    ) {
        if let Some(last) = batches.last_mut()
            && last.matches(&completion)
        {
            last.completions.push(completion);
            return;
        }
        batches.push(Self::from_completion(completion));
    }

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
        self.completions.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.completions.is_empty()
    }

    pub(crate) fn first_order(&self) -> Option<OrderToken> {
        self.completions.first().map(CryptoCompletion::order)
    }

    pub(crate) fn owner_shard(&self) -> usize {
        self.owner_shard
    }

    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn source(&self) -> CryptoCompletionSource {
        self.source
    }

    pub(crate) fn is_open_fsp_session_payload_run(&self) -> bool {
        !self.completions.is_empty()
            && self.source == CryptoCompletionSource::Open
            && self.owner.protocol() == PacketProtocol::Fsp
            && self.completions.iter().all(|completion| {
                matches!(
                    &completion.result,
                    CryptoResult::Opened(output)
                        if matches!(output.target(), OutputTarget::SessionPayload { .. })
                )
            })
    }

    pub(crate) fn split_off(&mut self, at: usize) -> Self {
        Self {
            owner_shard: self.owner_shard,
            owner: self.owner,
            generation: self.generation,
            lane: self.lane,
            source: self.source,
            completions: self.completions.split_off(at),
        }
    }

    pub(crate) fn into_completions(self) -> Vec<CryptoCompletion> {
        self.completions
    }

    fn matches(&self, completion: &CryptoCompletion) -> bool {
        self.owner_shard == completion.reservation.owner_shard()
            && self.owner == completion.reservation.owner
            && self.generation == completion.reservation.generation
            && self.lane == completion.reservation.lane
            && self.source == completion.source()
            && self
                .completions
                .last()
                .map_or(true, |last| last.order().next() == completion.order())
    }
}

fn completion_run_is_contiguous(
    completions: &[CryptoCompletion],
    owner_shard: usize,
    owner: OwnerId,
    generation: u64,
    lane: Lane,
    source: CryptoCompletionSource,
) -> bool {
    let mut expected = completions.first().map(CryptoCompletion::order);
    for completion in completions {
        if completion.reservation.owner_shard() != owner_shard
            || completion.reservation.owner != owner
            || completion.reservation.generation != generation
            || completion.reservation.lane != lane
            || completion.source() != source
            || Some(completion.order()) != expected
        {
            return false;
        }
        expected = Some(completion.order().next());
    }
    true
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

    pub(crate) fn path(&self) -> Option<TransportPath> {
        self.path.clone()
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
        &self.payload
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
}

impl DataplaneTransportSentReceipt {
    pub(crate) fn from_output(output: &PacketOutput) -> Self {
        Self {
            owner: output.owner,
            counter: output.counter,
            fmp_timestamp_ms: output.fmp_timestamp_ms,
            payload_len: output.payload.len(),
            fsp_send_receipt: output.fsp_send_receipt,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFspSendReceipt {
    owner: OwnerId,
    counter: u64,
    timestamp_ms: Option<u32>,
}

impl DataplaneFspSendReceipt {
    pub(crate) fn new(owner: OwnerId, counter: u64, timestamp_ms: Option<u32>) -> Self {
        Self {
            owner,
            counter,
            timestamp_ms,
        }
    }

    pub(crate) fn owner(self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(self) -> u64 {
        self.counter
    }

    pub(crate) fn timestamp_ms(self) -> Option<u32> {
        self.timestamp_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetiredPacket {
    Output(PacketOutput),
    Outbound(OutboundPacket),
    Drop(PacketDrop),
}

#[derive(Clone, Debug)]
pub(crate) struct RetiredOutputs {
    items: Vec<RetiredOutput>,
}

#[derive(Clone, Debug)]
pub(crate) enum RetiredOutput {
    Packet(RetiredPacket),
    EndpointDataBatch(DataplaneEndpointDataBatch),
}

impl RetiredOutputs {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn into_items(self) -> Vec<RetiredOutput> {
        self.items
    }

    pub(crate) fn push_output(&mut self, output: PacketOutput) {
        self.push_packet(RetiredPacket::Output(output));
    }

    pub(crate) fn push_outbound(&mut self, packet: OutboundPacket) {
        self.push_packet(RetiredPacket::Outbound(packet));
    }

    pub(crate) fn push_drop(&mut self, drop: PacketDrop) {
        self.push_packet(RetiredPacket::Drop(drop));
    }

    pub(crate) fn push_endpoint_data_batch(
        &mut self,
        ingress: DataplaneFspEndpointDataIngress,
    ) {
        match self.items.last_mut() {
            Some(RetiredOutput::EndpointDataBatch(batch)) => batch.push(ingress),
            _ => self.items.push(RetiredOutput::EndpointDataBatch(
                DataplaneEndpointDataBatch::from_ingress(ingress),
            )),
        }
    }

    pub(crate) fn append_endpoint_data_batch(&mut self, batch: DataplaneEndpointDataBatch) {
        match self.items.last_mut() {
            Some(RetiredOutput::EndpointDataBatch(last)) => last.extend(batch),
            _ => self.items.push(RetiredOutput::EndpointDataBatch(batch)),
        }
    }

    pub(crate) fn append_drops_to(&self, drops: &mut Vec<PacketDrop>) {
        for item in &self.items {
            if let RetiredOutput::Packet(RetiredPacket::Drop(drop)) = item {
                drops.push(drop.clone());
            }
        }
    }

    pub(crate) fn append_missing_drops_to(
        &self,
        drops: &mut Vec<PacketDrop>,
        emitted_start: usize,
    ) {
        for item in &self.items {
            if let RetiredOutput::Packet(RetiredPacket::Drop(drop)) = item
                && !drops[emitted_start..].iter().any(|emitted| emitted == drop)
            {
                drops.push(drop.clone());
            }
        }
    }

    fn push_packet(&mut self, packet: RetiredPacket) {
        self.items.push(RetiredOutput::Packet(packet));
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
