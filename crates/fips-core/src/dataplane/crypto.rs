use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering::Acquire, Ordering::AcqRel, Ordering::Relaxed};

pub(crate) enum PreparedCryptoWork {
    Open { work: CryptoWork, cipher: AeadKey },
    Seal { work: OutboundCryptoWork, cipher: AeadKey },
}

const DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS: usize = 8;
const DATAPLANE_AEAD_JOB_PACKETS: usize = 128;

impl PreparedCryptoWork {
    pub(crate) fn open(work: CryptoWork, cipher: AeadKey) -> Self {
        Self::Open { work, cipher }
    }

    pub(crate) fn seal(work: OutboundCryptoWork, cipher: AeadKey) -> Self {
        Self::Seal { work, cipher }
    }

    fn lane(&self) -> Lane {
        match self {
            Self::Open { work, .. } => work.reservation.lane,
            Self::Seal { work, .. } => work.reservation.lane,
        }
    }

    fn reservation(&self) -> &OwnerReservation {
        match self {
            Self::Open { work, .. } => &work.reservation,
            Self::Seal { work, .. } => &work.reservation,
        }
    }

    fn cipher(&self) -> &AeadKey {
        match self {
            Self::Open { cipher, .. } | Self::Seal { cipher, .. } => cipher,
        }
    }

    fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }

    fn is_open_fsp_session_payload(&self) -> bool {
        match self {
            Self::Open { work, .. } => work.is_open_fsp_session_payload(),
            Self::Seal { .. } => false,
        }
    }

    fn into_owner_item(self) -> (CryptoOwnerRunItem, AeadKey) {
        match self {
            Self::Open { work, cipher } => (CryptoOwnerRunItem::open(work), cipher),
            Self::Seal { work, cipher } => (CryptoOwnerRunItem::seal(work), cipher),
        }
    }
}

struct CryptoOwnerRunBuilder {
    cipher: Option<AeadKey>,
    run: Option<CryptoOwnerRun>,
}

impl CryptoOwnerRunBuilder {
    fn new() -> Self {
        Self {
            cipher: None,
            run: None,
        }
    }

    fn push(
        &mut self,
        pool: &mut DataplaneAeadWorkerPool,
        work: PreparedCryptoWork,
        stage: &mut impl FnMut(Arc<CryptoReadySlot>),
    ) {
        if !self.matches_run(&work)
            || self
                .run
                .as_ref()
                .is_some_and(|run| run.len() >= DATAPLANE_AEAD_JOB_PACKETS)
        {
            self.flush(pool, stage);
        }
        let (work, cipher) = work.into_owner_item();
        match &mut self.run {
            Some(run) => run.push(work),
            None => {
                self.run = Some(CryptoOwnerRun::new(work, DATAPLANE_AEAD_JOB_PACKETS));
                self.cipher = Some(cipher);
            }
        }
    }

    fn flush(
        &mut self,
        pool: &mut DataplaneAeadWorkerPool,
        stage: &mut impl FnMut(Arc<CryptoReadySlot>),
    ) {
        let Some(run) = self.run.take() else {
            return;
        };
        let cipher = self
            .cipher
            .take()
            .expect("crypto run cipher exists when work is non-empty");
        let run = pool.prepare_owner_run(run, cipher);
        stage(Arc::clone(&run.slot));
        pool.submit_owner_run(run);
    }

    fn matches_run(&self, work: &PreparedCryptoWork) -> bool {
        let Some(run) = self.run.as_ref() else {
            return true;
        };
        let Some(current_cipher) = self.cipher.as_ref() else {
            return true;
        };
        Arc::ptr_eq(current_cipher, work.cipher())
            && run.matches(
                work.reservation(),
                work.is_open(),
                work.is_open_fsp_session_payload(),
            )
    }
}

#[derive(Clone, Debug)]
struct DataplaneAeadWorkerCounters {
    in_flight: Arc<AtomicUsize>,
    bulk_in_flight: Arc<AtomicUsize>,
    ready: Arc<AtomicUsize>,
}

impl DataplaneAeadWorkerCounters {
    fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicUsize::new(0)),
            bulk_in_flight: Arc::new(AtomicUsize::new(0)),
            ready: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn add(&self, count: usize, bulk_count: usize) {
        self.in_flight.fetch_add(count, Relaxed);
        if bulk_count > 0 {
            self.bulk_in_flight.fetch_add(bulk_count, Relaxed);
        }
    }

    fn mark_ready(&self, count: usize) {
        self.ready.fetch_add(count, Relaxed);
    }

    fn retire(&self, count: usize, bulk_count: usize) {
        self.in_flight.fetch_sub(count, Relaxed);
        self.ready.fetch_sub(count, Relaxed);
        if bulk_count > 0 {
            self.bulk_in_flight.fetch_sub(bulk_count, Relaxed);
        }
    }
}

#[derive(Debug)]
pub(crate) struct CryptoReadySlot {
    owner_shard: usize,
    owner: OwnerId,
    generation: u64,
    lane: Lane,
    first_order: OrderToken,
    len: usize,
    open_fsp_session_payload: bool,
    remaining_jobs: AtomicUsize,
    results: Mutex<Box<[Option<CryptoCompletion>]>>,
    counters: Option<DataplaneAeadWorkerCounters>,
}

impl CryptoReadySlot {
    fn new(
        run: &CryptoOwnerRun,
        jobs: usize,
        counters: DataplaneAeadWorkerCounters,
    ) -> Self {
        let reservation = run
            .first_reservation()
            .expect("crypto owner run contains work");
        Self {
            owner_shard: reservation.owner_shard(),
            owner: reservation.owner,
            generation: reservation.generation,
            lane: reservation.lane,
            first_order: reservation.order,
            len: run.len(),
            open_fsp_session_payload: run.is_open_fsp_session_payload_run(),
            remaining_jobs: AtomicUsize::new(jobs),
            results: Mutex::new((0..run.len()).map(|_| None).collect()),
            counters: Some(counters),
        }
    }

    pub(crate) fn completed(completion: CryptoCompletion) -> Arc<Self> {
        Self::completed_run(vec![completion])
    }

    fn completed_run(completions: Vec<CryptoCompletion>) -> Arc<Self> {
        let reservation = &completions
            .first()
            .expect("completed owner slot contains a result")
            .reservation;
        debug_assert!(completions.iter().enumerate().all(|(index, completion)| {
            completion.reservation.owner_shard() == reservation.owner_shard()
                && completion.reservation.owner == reservation.owner
                && completion.reservation.generation == reservation.generation
                && completion.reservation.lane == reservation.lane
                && completion.reservation.order.0
                    == reservation.order.0.wrapping_add(index as u64)
        }));
        Arc::new(Self {
            owner_shard: reservation.owner_shard(),
            owner: reservation.owner,
            generation: reservation.generation,
            lane: reservation.lane,
            first_order: reservation.order,
            len: completions.len(),
            open_fsp_session_payload: false,
            remaining_jobs: AtomicUsize::new(0),
            results: Mutex::new(
                completions
                    .into_iter()
                    .map(Some)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            counters: None,
        })
    }

    fn complete(&self, start: usize, completions: Vec<CryptoCompletion>) -> bool {
        let end = start.saturating_add(completions.len());
        assert!(end <= self.len(), "AEAD result range exceeds its owner slot");
        let mut results = self.results.lock().expect("AEAD result slot poisoned");
        for (slot, completion) in results[start..end].iter_mut().zip(completions) {
            assert!(slot.replace(completion).is_none(), "AEAD result written twice");
        }
        drop(results);

        let remaining = self.remaining_jobs.fetch_sub(1, AcqRel);
        assert!(remaining > 0, "AEAD readiness decremented after completion");
        if remaining != 1 {
            return false;
        }
        if let Some(counters) = &self.counters {
            counters.mark_ready(self.len());
        }
        crate::perf_profile::record_dataplane_aead_ready_slot(self.len());
        true
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.remaining_jobs.load(Acquire) == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn drain_results(
        &self,
        start: usize,
        limit: usize,
        mut consume: impl FnMut(CryptoCompletion),
    ) -> usize {
        assert!(self.is_ready(), "owner retired an unready AEAD slot");
        let mut results = self.results.lock().expect("AEAD result slot poisoned");
        let end = start.saturating_add(limit).min(results.len());
        for result in &mut results[start..end] {
            consume(result.take().expect("ready AEAD result missing"));
        }
        let drained = end.saturating_sub(start);
        if let Some(counters) = &self.counters {
            let bulk_count = if self.lane == Lane::Bulk { drained } else { 0 };
            counters.retire(drained, bulk_count);
        }
        drained
    }

    pub(crate) fn is_open_fsp_session_payload_run(&self) -> bool {
        if !self.open_fsp_session_payload || !self.is_ready() {
            return false;
        }
        self.results
            .lock()
            .expect("AEAD result slot poisoned")
            .iter()
            .all(|completion| {
                matches!(
                    completion.as_ref().map(|completion| &completion.result),
                    Some(CryptoResult::Opened(output))
                        if matches!(output.target(), OutputTarget::SessionPayload { .. })
                )
            })
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

    pub(crate) fn first_order(&self) -> OrderToken {
        self.first_order
    }
}

#[derive(Debug)]
struct PreparedCryptoOwnerRun {
    slot: Arc<CryptoReadySlot>,
    cipher: AeadKey,
    items: Vec<CryptoOwnerRunItem>,
}

#[derive(Debug)]
pub(crate) struct DataplaneAeadWorkerPool {
    readiness_notify: Arc<tokio::sync::Notify>,
    counters: DataplaneAeadWorkerCounters,
    max_in_flight: usize,
    runtime: Option<tokio::runtime::Handle>,
    tasks: tokio::task::JoinSet<()>,
}

impl DataplaneAeadWorkerPool {
    pub(crate) fn new(max_in_flight: usize) -> Self {
        let max_in_flight = max_in_flight.max(1);

        Self {
            readiness_notify: Arc::new(tokio::sync::Notify::new()),
            counters: DataplaneAeadWorkerCounters::new(),
            max_in_flight,
            runtime: tokio::runtime::Handle::try_current().ok(),
            tasks: tokio::task::JoinSet::new(),
        }
    }

    pub(crate) fn readiness_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.readiness_notify)
    }

    pub(crate) fn record_perf_depths(&mut self) {
        self.reap_finished_tasks();
        if !crate::perf_profile::enabled() {
            return;
        }
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadInFlight,
            self.counters.in_flight.load(Relaxed) as u64,
        );
        let completion_depth = self.counters.ready.load(Relaxed);
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadReadyPackets,
            completion_depth as u64,
        );
    }

    fn available_capacity(&self) -> usize {
        self.max_in_flight.saturating_sub(
            self.counters.in_flight.load(Relaxed),
        )
    }

    fn available_capacity_for_lane(&self, lane: Lane) -> usize {
        let total_available = self.available_capacity();
        if lane == Lane::Priority {
            return total_available;
        }
        let bulk_limit =
            self.max_in_flight
                .saturating_sub(dataplane_aead_worker_priority_reserve(
                    self.max_in_flight,
                ));
        let bulk_in_flight = self
            .counters
            .bulk_in_flight
            .load(Relaxed);
        bulk_limit.saturating_sub(bulk_in_flight).min(total_available)
    }

    fn prepare_owner_run(
        &self,
        run: CryptoOwnerRun,
        cipher: AeadKey,
    ) -> PreparedCryptoOwnerRun {
        let len = run.len();
        let bulk_count = run.bulk_count();
        self.counters.add(len, bulk_count);
        let slot = Arc::new(CryptoReadySlot::new(&run, 1, self.counters.clone()));
        PreparedCryptoOwnerRun {
            slot,
            cipher,
            items: run.items,
        }
    }

    fn submit_owner_run(&mut self, run: PreparedCryptoOwnerRun) {
        self.reap_finished_tasks();
        let PreparedCryptoOwnerRun {
            slot,
            cipher,
            items,
        } = run;
        let runtime = self
            .runtime
            .get_or_insert_with(tokio::runtime::Handle::current)
            .clone();
        let run_len = items.len();
        let readiness_notify = Arc::clone(&self.readiness_notify);
        let queued_at = crate::perf_profile::stamp();
        self.tasks.spawn_on(
            async move {
                crate::perf_profile::record_since(
                    crate::perf_profile::Stage::DataplaneAeadWorkerQueueWait,
                    queued_at,
                );
                let completions = execute_crypto_owner_run(items, &cipher).await;
                crate::perf_profile::record_dataplane_aead_result_deposit(completions.len());
                if slot.complete(0, completions) {
                    readiness_notify.notify_one();
                }
            },
            &runtime,
        );
        crate::perf_profile::record_dataplane_aead_prepared_job(run_len);
    }

    pub(crate) fn reap_finished_tasks(&mut self) {
        while let Some(result) = self.tasks.try_join_next() {
            result.expect("dataplane AEAD task failed");
        }
    }

    fn submit_prepared_chunk(
        &mut self,
        prepared: &mut Vec<PreparedCryptoWork>,
        mut stage: impl FnMut(Arc<CryptoReadySlot>),
    ) {
        if prepared.is_empty() {
            return;
        }

        let mut runs = CryptoOwnerRunBuilder::new();
        for work in prepared.drain(..) {
            runs.push(self, work, &mut stage);
        }
        runs.flush(self, &mut stage);
    }
}

async fn execute_crypto_owner_run(
    items: Vec<CryptoOwnerRunItem>,
    cipher: &AeadKey,
) -> Vec<CryptoCompletion> {
    let is_open = items.first().is_some_and(CryptoOwnerRunItem::is_open);
    let mut items = items.into_iter();
    let mut completions = Vec::with_capacity(items.len());
    while !items.as_slice().is_empty() {
        {
            let _open_timer = is_open.then(|| {
                crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneAeadOpen)
            });
            for item in items
                .by_ref()
                .take(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS)
            {
                let result = match item.state {
                    CryptoOwnerRunItemState::Open(packet) => {
                        execute_open_crypto_work(packet, &item.reservation, cipher)
                    }
                    CryptoOwnerRunItemState::Seal(packet) => {
                        execute_seal_crypto_work(packet, &item.reservation, cipher)
                    }
                };
                completions.push(CryptoCompletion {
                    reservation: item.reservation,
                    result,
                });
            }
        }
        if !items.as_slice().is_empty() {
            tokio::task::yield_now().await;
        }
    }
    completions
}

fn dataplane_aead_worker_priority_reserve(max_in_flight: usize) -> usize {
    max_in_flight
        .saturating_sub(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS)
        .min(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS)
}

impl std::fmt::Debug for PreparedCryptoWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { work, .. } => f
                .debug_struct("PreparedCryptoWork::Open")
                .field("reservation", &work.reservation)
                .finish_non_exhaustive(),
            Self::Seal { work, .. } => f
                .debug_struct("PreparedCryptoWork::Seal")
                .field("reservation", &work.reservation)
                .finish_non_exhaustive(),
        }
    }
}

fn failed_crypto_completion(
    reservation: OwnerReservation,
    kind: CryptoFailureKind,
) -> CryptoCompletion {
    CryptoCompletion {
        reservation,
        result: CryptoResult::Failed(kind),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AeadHeader {
    Fmp([u8; FMP_ESTABLISHED_HEADER_SIZE]),
    Fsp([u8; FSP_HEADER_SIZE]),
}

impl AeadHeader {
    fn as_aad(&self) -> &[u8] {
        match self {
            Self::Fmp(header) => header,
            Self::Fsp(header) => header,
        }
    }
}

fn execute_open_crypto_work(
    mut packet: SocketPacket,
    reservation: &OwnerReservation,
    cipher: &LessSafeKey,
) -> CryptoResult {
    let parsed = match packet.owner.protocol {
        PacketProtocol::Fmp => FmpWireHeader::parse(packet.payload.as_slice()).map(|header| {
            (
                AeadHeader::Fmp(header.header_bytes()),
                header.ciphertext_offset(),
                header.counter(),
            )
        }),
        PacketProtocol::Fsp => FspWireHeader::parse(packet.payload.as_slice()).map(|header| {
            (
                AeadHeader::Fsp(header.header_bytes()),
                header.ciphertext_offset(),
                header.counter(),
            )
        }),
    };
    let Ok((header, ciphertext_offset, counter)) = parsed else {
        return CryptoResult::Failed(CryptoFailureKind::Open);
    };
    if counter != packet.counter {
        return CryptoResult::Failed(CryptoFailureKind::Open);
    }

    let target = packet.output;
    let source_wire_len = packet.payload.len();
    let plaintext_len = {
        let Some(ciphertext) = packet.payload.as_mut_slice().get_mut(ciphertext_offset..) else {
            return CryptoResult::Failed(CryptoFailureKind::Open);
        };
        let nonce = aead_nonce(reservation.counter);
        let Ok(plaintext) = cipher.open_in_place(nonce, Aad::from(header.as_aad()), ciphertext)
        else {
            return CryptoResult::Failed(CryptoFailureKind::Open);
        };
        plaintext.len()
    };
    packet.payload.truncate(ciphertext_offset + plaintext_len);
    CryptoResult::Opened(PacketOutput {
        owner: reservation.owner,
        counter: reservation.counter,
        ingress_seq: reservation.ingress_seq,
        lane: reservation.lane,
        target,
        source_path: reservation.source_path.clone(),
        previous_hop: reservation.previous_hop,
        ce_flag: reservation.ce_flag,
        path_mtu: reservation.path_mtu,
        source_peer: reservation.source_peer,
        path: reservation.output_path.clone(),
        activity_tick: reservation.activity_tick,
        fmp_timestamp_ms: reservation.fmp_timestamp_ms,
        source_wire_len: Some(source_wire_len),
        fsp_send_receipt: None,
        send_token: reservation.send_token,
        payload: packet.payload,
    })
}

fn execute_seal_crypto_work(
    mut packet: OutboundPacket,
    reservation: &OwnerReservation,
    cipher: &LessSafeKey,
) -> CryptoResult {
    let _timer = crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneAeadSeal);
    let inner_prefix = match packet.crypto_plaintext_prefix(
        reservation.fmp_timestamp_ms,
        reservation.fsp_timestamp_ms,
    ) {
        Ok(prefix) => prefix,
        Err(_) => return CryptoResult::Failed(CryptoFailureKind::Seal),
    };
    let Ok(payload_len) = u16::try_from(inner_prefix.len().saturating_add(packet.payload.len()))
    else {
        return CryptoResult::Failed(CryptoFailureKind::Seal);
    };
    let (header, coord_prefix, ciphertext_offset) = match (packet.owner.protocol, packet.wire) {
            (
                PacketProtocol::Fmp,
                OutboundWire::Fmp {
                    receiver_idx,
                    flags,
                },
            ) => (
                AeadHeader::Fmp(build_fmp_established_header(
                    receiver_idx,
                    reservation.counter,
                    flags,
                    payload_len,
                )),
                Vec::new(),
                FMP_ESTABLISHED_HEADER_SIZE,
            ),
            (PacketProtocol::Fsp, OutboundWire::Fsp { flags }) => {
                let coord_prefix = std::mem::take(&mut packet.fsp_cleartext_prefix);
                if validate_fsp_cleartext_prefix(flags, &coord_prefix).is_err() {
                    return CryptoResult::Failed(CryptoFailureKind::Seal);
                }
                let ciphertext_offset = FSP_HEADER_SIZE + coord_prefix.len();
                let Ok(header) = build_fsp_established_header(
                    reservation.counter,
                    flags,
                    payload_len,
                ) else {
                    return CryptoResult::Failed(CryptoFailureKind::Seal);
                };
                (
                    AeadHeader::Fsp(header),
                    coord_prefix,
                    ciphertext_offset,
                )
            }
            _ => return CryptoResult::Failed(CryptoFailureKind::Seal),
        };

    let aad = header.as_aad();
    let aad_len = aad.len();
    let prefix_len = aad
        .len()
        .saturating_add(coord_prefix.len())
        .saturating_add(inner_prefix.len());
    if packet.payload.try_prepend_slices(
        &[aad, coord_prefix.as_slice(), inner_prefix.as_slice()],
        AEAD_TAG_SIZE,
    ) {
        crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneSealInPlace);
    } else {
        crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneSealAllocated);
        let plaintext = std::mem::take(&mut packet.payload);
        let mut payload = Vec::with_capacity(
            prefix_len
                .saturating_add(plaintext.len())
                .saturating_add(AEAD_TAG_SIZE),
        );
        payload.extend_from_slice(aad);
        payload.extend_from_slice(&coord_prefix);
        payload.extend_from_slice(&inner_prefix);
        payload.extend_from_slice(plaintext.as_slice());
        packet.payload = PacketBuffer::new(payload);
    }

    if aad_len > ciphertext_offset || ciphertext_offset > packet.payload.len() {
        return CryptoResult::Failed(CryptoFailureKind::Seal);
    }
    let nonce = aead_nonce(reservation.counter);
    let (prefix, plaintext) = packet
        .payload
        .as_mut_slice()
        .split_at_mut(ciphertext_offset);
    let Some(aad) = prefix.get(..aad_len) else {
        return CryptoResult::Failed(CryptoFailureKind::Seal);
    };
    let Ok(tag) = cipher.seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext) else {
        return CryptoResult::Failed(CryptoFailureKind::Seal);
    };
    packet.payload.extend_from_slice(tag.as_ref());

    match packet.post_seal {
        OutboundPostSeal::Transport => CryptoResult::Sealed(PacketOutput {
            owner: reservation.owner,
            counter: reservation.counter,
            ingress_seq: reservation.ingress_seq,
            lane: reservation.lane,
            target: OutputTarget::Transport,
            source_path: reservation.source_path.clone(),
            previous_hop: reservation.previous_hop,
            ce_flag: reservation.ce_flag,
            path_mtu: reservation.path_mtu,
            source_peer: reservation.source_peer,
            path: reservation.output_path.clone(),
            activity_tick: reservation.activity_tick,
            fmp_timestamp_ms: reservation.fmp_timestamp_ms,
            source_wire_len: None,
            fsp_send_receipt: packet.fsp_send_receipt,
            send_token: reservation.send_token,
            payload: packet.payload,
        }),
        OutboundPostSeal::FmpWrap(route) => {
            let mut output = route
                .into_fmp_outbound(packet.class, packet.payload)
                .with_fsp_send_receipt(DataplaneFspSendReceipt {
                    owner: reservation.owner,
                    counter: reservation.counter,
                });
            if let Some(send_token) = packet.send_token {
                output = output.with_send_token(send_token);
            }
            if let Some(tick) = reservation.activity_tick {
                output = output.with_activity_tick(tick);
            }
            CryptoResult::Outbound(output)
        }
    }
}

fn validate_fsp_cleartext_prefix(flags: u8, prefix: &[u8]) -> Result<(), WireBuildError> {
    if flags & crate::node::session_wire::FSP_FLAG_CP == 0 {
        return if prefix.is_empty() {
            Ok(())
        } else {
            Err(WireBuildError::BadFspCoords)
        };
    }

    crate::node::session_wire::parse_encrypted_coords(prefix)
        .map(|_| ())
        .map_err(|_| WireBuildError::BadFspCoords)
}

fn aead_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}
