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
    owner_shard: usize,
    owner: OwnerId,
    generation: u64,
    lane: Lane,
    first_order: OrderToken,
    len: usize,
    open_fsp_session_payload: bool,
    subruns: Box<[std::sync::Mutex<VecDeque<CryptoOwnerRunItem>>]>,
    remaining_subruns: std::sync::atomic::AtomicUsize,
    worker_counted: bool,
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
    fn new(
        items: Vec<CryptoOwnerRunItem>,
        max_subruns: usize,
        worker_counted: bool,
    ) -> Arc<Self> {
        let first = items.first().expect("crypto owner run contains work");
        let owner_shard = first.reservation.owner_shard();
        let owner = first.reservation.owner;
        let generation = first.reservation.generation;
        let lane = first.reservation.lane;
        let first_order = first.reservation.order;
        let len = items.len();
        let open_fsp_session_payload = first.is_open_fsp_session_payload();
        let subrun_count = if worker_counted {
            len.div_ceil(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS)
                .min(max_subruns.max(1))
                .max(1)
        } else {
            1
        };
        let subrun_len = len.div_ceil(subrun_count);
        let mut items = items.into_iter();
        let mut subruns = Vec::with_capacity(subrun_count);
        while items.len() > 0 {
            subruns.push(std::sync::Mutex::new(
                items
                    .by_ref()
                    .take(subrun_len)
                    .collect::<VecDeque<_>>(),
            ));
        }
        debug_assert_eq!(subruns.len(), subrun_count);
        Arc::new(Self {
            owner_shard,
            owner,
            generation,
            lane,
            first_order,
            len,
            open_fsp_session_payload,
            subruns: subruns.into_boxed_slice(),
            remaining_subruns: std::sync::atomic::AtomicUsize::new(if worker_counted {
                subrun_count
            } else {
                0
            }),
            worker_counted,
        })
    }

    fn ready(&self) -> CryptoOwnerReady {
        CryptoOwnerReady {
            owner_shard: self.owner_shard,
            owner: self.owner,
            packets: self.len,
        }
    }

    fn is_ready(&self) -> bool {
        self.remaining_subruns
            .load(std::sync::atomic::Ordering::Acquire)
            == 0
    }

    fn finish_subrun(&self) -> bool {
        self.remaining_subruns
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
    }

    fn prefix_is_open_fsp_session_payload(&self, count: usize) -> bool {
        if count == 0
            || self.owner.protocol() != PacketProtocol::Fsp
            || !self.open_fsp_session_payload
        {
            return false;
        }
        let mut remaining = count;
        for subrun in &self.subruns {
            let subrun = subrun.lock().expect("crypto owner subrun lock poisoned");
            for item in subrun.iter().take(remaining) {
                if !item.is_open_fsp_session_payload() {
                    return false;
                }
                remaining -= 1;
            }
            if remaining == 0 {
                return true;
            }
        }
        false
    }

    fn consume_prefix(&self, count: usize, mut consume: impl FnMut(CryptoCompletion)) {
        let mut remaining = count;
        for subrun in &self.subruns {
            let mut subrun = subrun.lock().expect("crypto owner subrun lock poisoned");
            while remaining > 0 {
                let Some(item) = subrun.pop_front() else {
                    break;
                };
                consume(item.into_completion());
                remaining -= 1;
            }
            if remaining == 0 {
                break;
            }
        }
        assert_eq!(remaining, 0, "crypto owner run prefix exceeds remaining work");
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CryptoOwnerReady {
    owner_shard: usize,
    owner: OwnerId,
    packets: usize,
}

#[derive(Debug)]
struct PendingCryptoOwnerRun {
    run: Arc<CryptoOwnerRun>,
    next_order: OrderToken,
    remaining: usize,
}

impl PendingCryptoOwnerRun {
    fn new(run: Arc<CryptoOwnerRun>) -> Self {
        Self {
            next_order: run.first_order,
            remaining: run.len,
            run,
        }
    }

    fn is_ready(&self) -> bool {
        self.run.is_ready()
    }

    fn is_empty(&self) -> bool {
        self.remaining == 0
    }

    fn lane(&self) -> Lane {
        self.run.lane
    }

    fn generation(&self) -> u64 {
        self.run.generation
    }

    fn worker_counted(&self) -> bool {
        self.run.worker_counted
    }

    fn prefix_is_open_fsp_session_payload(&self, count: usize) -> bool {
        self.run.prefix_is_open_fsp_session_payload(count)
    }

    fn consume_prefix(&mut self, count: usize, consume: impl FnMut(CryptoCompletion)) {
        assert!(count <= self.remaining, "crypto owner run prefix exceeds run");
        self.run.consume_prefix(count, consume);
        self.next_order = OrderToken(self.next_order.0.wrapping_add(count as u64));
        self.remaining -= count;
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

    fn failed(completion: CryptoCompletion) -> Self {
        Self {
            reservation: completion.reservation,
            state: CryptoOwnerRunItemState::Completed(completion.result),
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
