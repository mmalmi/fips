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
    state: std::cell::UnsafeCell<CryptoOwnerRunItemState>,
}

// A prepared run partitions items into disjoint subruns. Each item has one crypto
// writer, and owner reads begin only after the run's release/acquire ready barrier.
unsafe impl Sync for CryptoOwnerRunItem {}

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

}

impl CryptoOwnerRunItem {
    fn open(work: CryptoWork) -> Self {
        let CryptoWork {
            reservation,
            packet,
        } = work;
        Self {
            reservation,
            state: std::cell::UnsafeCell::new(CryptoOwnerRunItemState::Open(packet)),
        }
    }

    fn seal(work: OutboundCryptoWork) -> Self {
        let OutboundCryptoWork {
            reservation,
            packet,
        } = work;
        Self {
            reservation,
            state: std::cell::UnsafeCell::new(CryptoOwnerRunItemState::Seal(packet)),
        }
    }

    fn completed(completion: CryptoCompletion) -> Self {
        Self {
            reservation: completion.reservation,
            state: std::cell::UnsafeCell::new(CryptoOwnerRunItemState::Completed(
                completion.result,
            )),
        }
    }

    fn into_completion(self) -> CryptoCompletion {
        let CryptoOwnerRunItemState::Completed(result) = self.state.into_inner() else {
            panic!("owner retired unfinished crypto work")
        };
        CryptoCompletion {
            reservation: self.reservation,
            result,
        }
    }

    fn is_open(&self) -> bool {
        // Run construction is single-threaded and finishes before workers can see it.
        match unsafe { &*self.state.get() } {
            CryptoOwnerRunItemState::Open(_) => true,
            CryptoOwnerRunItemState::Seal(_) => false,
            CryptoOwnerRunItemState::Completed(_) => panic!("completed crypto work regrouped"),
        }
    }

    fn is_open_fsp_session_payload(&self) -> bool {
        // Run construction is single-threaded and finishes before workers can see it.
        match unsafe { &*self.state.get() } {
            CryptoOwnerRunItemState::Open(packet) => {
                self.reservation.owner.protocol() == PacketProtocol::Fsp
                    && matches!(packet.output, OutputTarget::SessionPayload { .. })
            }
            CryptoOwnerRunItemState::Seal(_) => false,
            CryptoOwnerRunItemState::Completed(_) => panic!("completed crypto work regrouped"),
        }
    }

    /// # Safety
    /// Exactly one worker may mutate this item, and `complete_crypto` must follow once.
    unsafe fn begin_crypto(&self, failed: CryptoFailureKind) -> CryptoOwnerRunItemState {
        unsafe {
            std::mem::replace(
                &mut *self.state.get(),
                CryptoOwnerRunItemState::Completed(CryptoResult::Failed(failed)),
            )
        }
    }

    /// # Safety
    /// Must be called once by the same sole writer after `begin_crypto`.
    unsafe fn complete_crypto(&self, result: CryptoResult) {
        unsafe {
            *self.state.get() = CryptoOwnerRunItemState::Completed(result);
        }
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
    wire_flags: u8,
    opened_payload_offset: u16,
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
