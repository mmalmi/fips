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

#[derive(Clone, Debug)]
pub(crate) struct DataplaneOwnerReadiness {
    shards: Arc<[Arc<tokio::sync::Notify>]>,
}

impl DataplaneOwnerReadiness {
    fn new(shard_count: usize) -> Self {
        let shards = (0..shard_count.max(1))
            .map(|_| Arc::new(tokio::sync::Notify::new()))
            .collect::<Vec<_>>();
        Self {
            shards: Arc::from(shards),
        }
    }

    fn shard(&self, shard: usize) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.shards[shard % self.shards.len()])
    }

    fn wake(&self) {
        self.shards[0].notify_one();
    }

    pub(crate) async fn notified(&self) {
        let waits = self
            .shards
            .iter()
            .map(|notify| Box::pin(notify.notified()))
            .collect::<Vec<_>>();
        let _ = futures::future::select_all(waits).await;
    }
}

#[derive(Debug)]
struct CryptoOwnerRunDraft {
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

impl CryptoOwnerRunDraft {
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

    fn execute(&mut self, cipher: &AeadKey) {
        let state = std::mem::replace(
            &mut self.state,
            CryptoOwnerRunItemState::Completed(CryptoResult::Failed(CryptoFailureKind::Open)),
        );
        self.state = CryptoOwnerRunItemState::Completed(match state {
            CryptoOwnerRunItemState::Open(packet) => {
                execute_open_crypto_work(packet, &self.reservation, cipher)
            }
            CryptoOwnerRunItemState::Seal(packet) => {
                execute_seal_crypto_work(packet, &self.reservation, cipher)
            }
            CryptoOwnerRunItemState::Completed(_) => {
                panic!("crypto owner subrun executed twice")
            }
        });
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
struct CryptoOwnerRun {
    owner_shard: usize,
    owner: OwnerId,
    generation: u64,
    lane: Lane,
    first_order: OrderToken,
    len: usize,
    open_fsp_session_payload: bool,
    subruns: Vec<std::sync::Mutex<VecDeque<CryptoOwnerRunItem>>>,
    remaining_subruns: std::sync::atomic::AtomicUsize,
    ready: Arc<tokio::sync::Notify>,
    counters: Option<DataplaneAeadWorkerCounters>,
}

#[derive(Debug)]
struct OrderedCryptoOwnerRun {
    run: Arc<CryptoOwnerRun>,
    next_order: OrderToken,
    remaining: usize,
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

impl CryptoOwnerRun {
    fn new(
        draft: CryptoOwnerRunDraft,
        subrun_packets: usize,
        ready: Arc<tokio::sync::Notify>,
        counters: Option<DataplaneAeadWorkerCounters>,
    ) -> Self {
        let reservation = draft
            .first_reservation()
            .expect("crypto owner run contains work");
        let owner_shard = reservation.owner_shard();
        let owner = reservation.owner;
        let generation = reservation.generation;
        let lane = reservation.lane;
        let first_order = reservation.order;
        let len = draft.len();
        let open_fsp_session_payload = draft.open_fsp_session_payload;
        let mut items = draft.items.into_iter();
        let mut subruns = Vec::with_capacity(len.div_ceil(subrun_packets.max(1)));
        loop {
            let subrun = items
                .by_ref()
                .take(subrun_packets.max(1))
                .collect::<VecDeque<_>>();
            if subrun.is_empty() {
                break;
            }
            subruns.push(std::sync::Mutex::new(subrun));
        }
        let remaining_subruns = if counters.is_some() { subruns.len() } else { 0 };
        Self {
            owner_shard,
            owner,
            generation,
            lane,
            first_order,
            len,
            open_fsp_session_payload,
            subruns,
            remaining_subruns: std::sync::atomic::AtomicUsize::new(remaining_subruns),
            ready,
            counters,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn subrun_count(&self) -> usize {
        self.subruns.len()
    }

    fn subrun_len(&self, index: usize) -> usize {
        self.subruns[index]
            .lock()
            .expect("crypto owner subrun lock poisoned")
            .len()
    }

    fn is_ready(&self) -> bool {
        self.remaining_subruns
            .load(std::sync::atomic::Ordering::Acquire)
            == 0
    }

    fn notify_if_ready(&self) {
        if self.is_ready() {
            self.ready.notify_one();
        }
    }

    fn owner_shard(&self) -> usize {
        self.owner_shard
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn generation(&self) -> u64 {
        self.generation
    }

    fn lane(&self) -> Lane {
        self.lane
    }

    fn first_order(&self) -> OrderToken {
        self.first_order
    }

    fn execute_subrun(&self, index: usize, cipher: &AeadKey) {
        let mut items = self.subruns[index]
            .lock()
            .expect("crypto owner subrun lock poisoned");
        let _open_timer = items.front().and_then(|item| {
            item.is_open().then(|| {
                crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneAeadOpen)
            })
        });
        for item in items.iter_mut() {
            item.execute(cipher);
        }
        drop(items);
        if self
            .remaining_subruns
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.ready.notify_one();
        }
    }

    fn ready_prefix_is_open_fsp_session_payload(&self, mut count: usize) -> bool {
        if count == 0
            || !self.open_fsp_session_payload
            || self.owner.protocol() != PacketProtocol::Fsp
            || !self.is_ready()
        {
            return false;
        }
        for subrun in &self.subruns {
            let items = subrun
                .lock()
                .expect("crypto owner subrun lock poisoned");
            for item in items.iter().take(count) {
                if !item.is_open_fsp_session_payload() {
                    return false;
                }
            }
            count = count.saturating_sub(items.len());
            if count == 0 {
                return true;
            }
        }
        false
    }

    fn consume_ready_prefix(
        &self,
        mut count: usize,
        mut consume: impl FnMut(CryptoCompletion),
    ) -> usize {
        assert!(self.is_ready(), "crypto owner run retired before readiness");
        let requested = count;
        for subrun in &self.subruns {
            let mut items = subrun
                .lock()
                .expect("crypto owner subrun lock poisoned");
            while count > 0 {
                let Some(item) = items.pop_front() else {
                    break;
                };
                consume(item.into_completion());
                count -= 1;
            }
            if count == 0 {
                break;
            }
        }
        requested.saturating_sub(count)
    }

    fn finish_retired(&self, count: usize) {
        if let Some(counters) = &self.counters {
            counters.finish(count, if self.lane == Lane::Bulk { count } else { 0 });
        }
    }
}

impl OrderedCryptoOwnerRun {
    fn new(run: Arc<CryptoOwnerRun>) -> Self {
        Self {
            next_order: run.first_order(),
            remaining: run.len(),
            run,
        }
    }

    fn is_ready(&self) -> bool {
        self.run.is_ready()
    }

    fn is_empty(&self) -> bool {
        self.remaining == 0
    }

    fn first_order(&self) -> OrderToken {
        self.next_order
    }

    fn last_order_exclusive(&self) -> OrderToken {
        OrderToken(self.next_order.0.wrapping_add(self.remaining as u64))
    }

    fn consume_prefix(
        &mut self,
        limit: usize,
        consume: impl FnMut(CryptoCompletion),
    ) -> usize {
        let count = limit.min(self.remaining);
        let consumed = self.run.consume_ready_prefix(count, consume);
        self.remaining = self.remaining.saturating_sub(consumed);
        self.next_order = OrderToken(self.next_order.0.wrapping_add(consumed as u64));
        self.run.finish_retired(consumed);
        consumed
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
