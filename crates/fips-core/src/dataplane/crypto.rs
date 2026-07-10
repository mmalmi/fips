use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

pub(crate) enum PreparedCryptoWork {
    Open { work: CryptoWork, cipher: AeadKey },
    Seal { work: OutboundCryptoWork, cipher: AeadKey },
    Completed { completion: CryptoCompletion },
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

    pub(crate) fn failed(reservation: OwnerReservation, kind: CryptoFailureKind) -> Self {
        Self::Completed {
            completion: failed_crypto_completion(reservation, kind),
        }
    }

    fn lane(&self) -> Lane {
        match self {
            Self::Open { work, .. } => work.reservation.lane,
            Self::Seal { work, .. } => work.reservation.lane,
            Self::Completed { completion } => completion.reservation.lane,
        }
    }

    fn reservation(&self) -> &OwnerReservation {
        match self {
            Self::Open { work, .. } => &work.reservation,
            Self::Seal { work, .. } => &work.reservation,
            Self::Completed { completion } => &completion.reservation,
        }
    }

    fn cipher(&self) -> Option<&AeadKey> {
        match self {
            Self::Open { cipher, .. } | Self::Seal { cipher, .. } => Some(cipher),
            Self::Completed { .. } => None,
        }
    }

    fn is_open(&self) -> bool {
        match self {
            Self::Open { .. } => true,
            Self::Seal { .. } => false,
            Self::Completed { completion } => completion.result.is_open_family(),
        }
    }

    fn is_open_fsp_session_payload(&self) -> bool {
        match self {
            Self::Open { work, .. } => work.is_open_fsp_session_payload(),
            Self::Seal { .. } | Self::Completed { .. } => false,
        }
    }

    fn into_owner_item(self) -> (CryptoOwnerRunItem, Option<AeadKey>) {
        match self {
            Self::Open { work, cipher } => (CryptoOwnerRunItem::open(work), Some(cipher)),
            Self::Seal { work, cipher } => (CryptoOwnerRunItem::seal(work), Some(cipher)),
            Self::Completed { completion } => (CryptoOwnerRunItem::failed(completion), None),
        }
    }
}

struct CryptoOwnerRunBuilder {
    cipher: Option<AeadKey>,
    items: Vec<CryptoOwnerRunItem>,
}

impl CryptoOwnerRunBuilder {
    fn new() -> Self {
        Self {
            cipher: None,
            items: Vec::with_capacity(DATAPLANE_AEAD_JOB_PACKETS),
        }
    }

    fn push(
        &mut self,
        pool: &mut DataplaneAeadWorkerPool,
        queue_run: &mut impl FnMut(Arc<CryptoOwnerRun>),
        work: PreparedCryptoWork,
    ) {
        if !self.matches_run(&work)
            || self.items.len() >= DATAPLANE_AEAD_JOB_PACKETS
        {
            self.flush(pool, queue_run);
        }
        let (work, cipher) = work.into_owner_item();
        if self.items.is_empty() {
            self.cipher = cipher;
        }
        self.items.push(work);
    }

    fn flush(
        &mut self,
        pool: &mut DataplaneAeadWorkerPool,
        queue_run: &mut impl FnMut(Arc<CryptoOwnerRun>),
    ) {
        if self.items.is_empty() {
            return;
        }
        let items = std::mem::replace(
            &mut self.items,
            Vec::with_capacity(DATAPLANE_AEAD_JOB_PACKETS),
        );
        let cipher = self.cipher.take();
        let run = CryptoOwnerRun::new(items, pool.owner_subruns, cipher.is_some());
        queue_run(Arc::clone(&run));
        if let Some(cipher) = cipher {
            pool.submit_run(run, cipher);
        }
    }

    fn matches_run(&self, work: &PreparedCryptoWork) -> bool {
        let Some(first) = self.items.first() else {
            return true;
        };
        let cipher_matches = match (self.cipher.as_ref(), work.cipher()) {
            (Some(current), Some(next)) => Arc::ptr_eq(current, next),
            (None, None) => true,
            (Some(_), None) | (None, Some(_)) => false,
        };
        let last = self.items.last().expect("crypto owner run has a first item");
        let reservation = work.reservation();
        cipher_matches
            && first.reservation.owner_shard() == reservation.owner_shard()
            && first.reservation.owner == reservation.owner
            && first.reservation.generation == reservation.generation
            && first.reservation.lane == reservation.lane
            && last.reservation.order.next() == reservation.order
            && first.is_open() == work.is_open()
            && (!work.is_open() || first.reservation.source_path == reservation.source_path)
            && first.is_open_fsp_session_payload() == work.is_open_fsp_session_payload()
    }
}

#[derive(Clone, Debug)]
struct DataplaneAeadWorkerCounters {
    in_flight: Arc<AtomicUsize>,
    bulk_in_flight: Arc<AtomicUsize>,
}

impl DataplaneAeadWorkerCounters {
    fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicUsize::new(0)),
            bulk_in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn add(&self, count: usize, bulk_count: usize) {
        self.in_flight.fetch_add(count, Relaxed);
        if bulk_count > 0 {
            self.bulk_in_flight.fetch_add(bulk_count, Relaxed);
        }
    }

    fn finish(&self, count: usize, bulk_count: usize) {
        self.in_flight.fetch_sub(count, Relaxed);
        if bulk_count > 0 {
            self.bulk_in_flight.fetch_sub(bulk_count, Relaxed);
        }
    }
}

#[derive(Debug)]
pub(crate) struct DataplaneAeadWorkerPool {
    ready_tx: tokio::sync::mpsc::Sender<CryptoOwnerReady>,
    ready_rx: tokio::sync::mpsc::Receiver<CryptoOwnerReady>,
    completion_notify: Arc<tokio::sync::Notify>,
    counters: DataplaneAeadWorkerCounters,
    max_in_flight: usize,
    owner_subruns: usize,
    runtime: Option<tokio::runtime::Handle>,
    tasks: tokio::task::JoinSet<()>,
}

impl DataplaneAeadWorkerPool {
    pub(crate) fn new(max_in_flight: usize) -> Self {
        let max_in_flight = max_in_flight.max(1);
        let (ready_tx, ready_rx) = tokio::sync::mpsc::channel(max_in_flight);
        let runtime = tokio::runtime::Handle::try_current().ok();
        let owner_subruns = runtime
            .as_ref()
            .map(|runtime| runtime.metrics().num_workers().saturating_sub(1))
            .unwrap_or(1)
            .max(1);

        Self {
            ready_tx,
            ready_rx,
            completion_notify: Arc::new(tokio::sync::Notify::new()),
            counters: DataplaneAeadWorkerCounters::new(),
            max_in_flight,
            owner_subruns,
            runtime,
            tasks: tokio::task::JoinSet::new(),
        }
    }

    pub(crate) fn completion_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.completion_notify)
    }

    pub(crate) fn has_ready_completions(&self) -> bool {
        !self.ready_rx.is_empty()
    }

    fn drain_ready_owners(
        &mut self,
        limit: usize,
        mut ready: impl FnMut(CryptoOwnerReady),
    ) -> usize {
        self.reap_finished_tasks();
        let mut packets = 0usize;
        while packets < limit {
            let Ok(owner) = self.ready_rx.try_recv() else {
                break;
            };
            packets = packets.saturating_add(owner.packets);
            ready(owner);
        }
        self.reap_finished_tasks();
        packets
    }

    pub(crate) fn record_perf_depths(&self) {
        if !crate::perf_profile::enabled() {
            return;
        }
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadInFlight,
            self.counters.in_flight.load(Relaxed) as u64,
        );
        let rx_queued_messages = self.ready_rx.len();
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadCompletionQueueDepth,
            rx_queued_messages as u64,
        );
        crate::perf_profile::record_dataplane_aead_completion_backlog(
            rx_queued_messages,
            0,
            0,
        );
    }

    fn finish_retired(&self, count: usize, bulk_count: usize) {
        self.counters.finish(count, bulk_count);
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

    fn submit_run(&mut self, run: Arc<CryptoOwnerRun>, cipher: AeadKey) {
        self.reap_finished_tasks();
        let run_len = run.len;
        let bulk_count = if run.lane == Lane::Bulk { run_len } else { 0 };
        self.counters.add(run_len, bulk_count);
        let runtime = self
            .runtime
            .get_or_insert_with(tokio::runtime::Handle::current)
            .clone();
        for subrun in 0..run.subruns.len() {
            let queued_at = crate::perf_profile::stamp();
            let ready_tx = self.ready_tx.clone();
            let completion_notify = Arc::clone(&self.completion_notify);
            let counters = self.counters.clone();
            let run = Arc::clone(&run);
            let cipher = Arc::clone(&cipher);
            let subrun_len = run.subruns[subrun]
                .lock()
                .expect("crypto owner subrun lock poisoned")
                .len();
            self.tasks.spawn_on(
                async move {
                    crate::perf_profile::record_since(
                        crate::perf_profile::Stage::DataplaneAeadWorkerQueueWait,
                        queued_at,
                    );
                    execute_crypto_owner_subrun(&run, subrun, &cipher);
                    if !run.finish_subrun() {
                        return;
                    }
                    let ready = run.ready();
                    crate::perf_profile::record_dataplane_aead_completion_send(
                        1,
                        1,
                        ready.packets,
                    );
                    if ready_tx.send(ready).await.is_err() {
                        counters.finish(
                            ready.packets,
                            if run.lane == Lane::Bulk {
                                ready.packets
                            } else {
                                0
                            },
                        );
                        return;
                    }
                    completion_notify.notify_one();
                },
                &runtime,
            );
            crate::perf_profile::record_dataplane_aead_prepared_job(subrun_len);
        }
    }

    fn reap_finished_tasks(&mut self) {
        while let Some(result) = self.tasks.try_join_next() {
            result.expect("dataplane AEAD task failed");
        }
    }

    fn submit_prepared_chunk(
        &mut self,
        prepared: &mut Vec<PreparedCryptoWork>,
        mut queue_run: impl FnMut(Arc<CryptoOwnerRun>),
    ) {
        if prepared.is_empty() {
            return;
        }

        let mut runs = CryptoOwnerRunBuilder::new();
        for work in prepared.drain(..) {
            runs.push(self, &mut queue_run, work);
        }
        runs.flush(self, &mut queue_run);
    }
}

fn execute_crypto_owner_subrun(run: &CryptoOwnerRun, subrun: usize, cipher: &AeadKey) {
    let mut items = run.subruns[subrun]
        .lock()
        .expect("crypto owner subrun lock poisoned");
    let _open_timer = items.front().is_some_and(CryptoOwnerRunItem::is_open).then(|| {
        crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneAeadOpen)
    });
    for item in items.iter_mut() {
        let state = std::mem::replace(
            &mut item.state,
            CryptoOwnerRunItemState::Completed(CryptoResult::Failed(CryptoFailureKind::Open)),
        );
        let result = match state {
            CryptoOwnerRunItemState::Open(packet) => {
                execute_open_crypto_work(packet, &item.reservation, &cipher)
            }
            CryptoOwnerRunItemState::Seal(packet) => {
                execute_seal_crypto_work(packet, &item.reservation, &cipher)
            }
            CryptoOwnerRunItemState::Completed(_) => {
                panic!("crypto owner run executed twice")
            }
        };
        item.state = CryptoOwnerRunItemState::Completed(result);
    }
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
            Self::Completed { completion } => f
                .debug_struct("PreparedCryptoWork::Completed")
                .field("reservation", &completion.reservation)
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
