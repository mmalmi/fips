pub(crate) enum PreparedCryptoWork {
    Open { work: CryptoWork, cipher: AeadKey },
    Seal { work: OutboundCryptoWork, cipher: AeadKey },
    Completed(CryptoCompletion),
}

const PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS: usize = 8;

impl PreparedCryptoWork {
    pub(crate) fn open(work: CryptoWork, cipher: AeadKey) -> Self {
        Self::Open { work, cipher }
    }

    pub(crate) fn seal(work: OutboundCryptoWork, cipher: AeadKey) -> Self {
        Self::Seal { work, cipher }
    }

    pub(crate) fn failed(reservation: OwnerReservation, kind: CryptoFailureKind) -> Self {
        Self::Completed(failed_crypto_completion(reservation, kind))
    }

    pub(crate) fn execute(self) -> CryptoCompletion {
        match self {
            Self::Open { work, cipher } => {
                let reservation = work.reservation.clone();
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadOpen,
                );
                match AeadOpenWork::from_crypto_work(work, cipher) {
                    Ok(work) => work.execute(),
                    Err(_) => failed_crypto_completion(reservation, CryptoFailureKind::Open),
                }
            }
            Self::Seal {
                work,
                cipher,
            } => {
                let reservation = work.reservation.clone();
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadSeal,
                );
                match AeadSealWork::from_outbound_work(work, cipher) {
                    Ok(work) => work.execute(),
                    Err(_) => failed_crypto_completion(reservation, CryptoFailureKind::Seal),
                }
            }
            Self::Completed(completion) => completion,
        }
    }

    fn push_executor_failed_completions(self, completions: &mut Vec<CryptoCompletion>) {
        match self {
            Self::Open { work, .. } => completions.push(failed_crypto_completion(
                work.reservation,
                CryptoFailureKind::Open,
            )),
            Self::Seal { work, .. } => {
                completions.push(failed_crypto_completion(
                    work.reservation,
                    CryptoFailureKind::Seal,
                ));
            }
            Self::Completed(completion) => completions.push(completion),
        }
    }

    fn lane(&self) -> Lane {
        match self {
            Self::Open { work, .. } => work.reservation.lane,
            Self::Seal { work, .. } => work.reservation.lane,
            Self::Completed(completion) => completion.reservation.lane,
        }
    }
}

#[derive(Debug)]
struct PreparedCryptoJob {
    queued_at: Option<crate::perf_profile::TraceStamp>,
    work: Vec<PreparedCryptoWork>,
    bulk_count: usize,
}

struct PreparedCryptoJobBuilder {
    direction: PacketMover2AeadDirection,
    job_packets: usize,
    work: Vec<PreparedCryptoWork>,
    bulk_count: usize,
    closed: bool,
}

impl PreparedCryptoJobBuilder {
    fn new(direction: PacketMover2AeadDirection, job_packets: usize) -> Self {
        let job_packets = job_packets.max(1);
        Self {
            direction,
            job_packets,
            work: Vec::with_capacity(job_packets),
            bulk_count: 0,
            closed: false,
        }
    }

    fn push(
        &mut self,
        pool: &PacketMover2AeadWorkerPool,
        work: PreparedCryptoWork,
        completions: &mut Vec<CryptoCompletion>,
    ) {
        if self.closed {
            work.push_executor_failed_completions(completions);
            return;
        }
        if work.lane() == Lane::Bulk {
            self.bulk_count = self.bulk_count.saturating_add(1);
        }
        self.work.push(work);
        if self.work.len() >= self.job_packets {
            self.flush(pool, completions);
        }
    }

    fn flush(
        &mut self,
        pool: &PacketMover2AeadWorkerPool,
        completions: &mut Vec<CryptoCompletion>,
    ) {
        if self.work.is_empty() || self.closed {
            return;
        }
        let next = Vec::with_capacity(self.job_packets);
        let work = std::mem::replace(&mut self.work, next);
        let bulk_count = std::mem::take(&mut self.bulk_count);
        if !pool.submit_prepared_job(self.direction, work, bulk_count, completions) {
            self.closed = true;
        }
    }
}

pub(crate) trait PacketMover2CryptoExecutor {
    fn available_capacity(&self) -> usize {
        usize::MAX
    }

    fn available_open_capacity(&self) -> usize {
        self.available_capacity()
    }

    fn available_seal_capacity(&self) -> usize {
        self.available_capacity()
    }

    fn available_open_capacity_for_lane(&self, _lane: Lane) -> usize {
        self.available_open_capacity()
    }

    fn available_seal_capacity_for_lane(&self, _lane: Lane) -> usize {
        self.available_seal_capacity()
    }

    fn execute_prepared_chunk(
        &mut self,
        prepared: &mut Vec<PreparedCryptoWork>,
        completions: &mut Vec<CryptoCompletion>,
    ) -> usize;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketMover2AeadDirection {
    Open,
    Seal,
}

struct PacketMover2AeadDirectionCounts {
    open: usize,
    open_bulk: usize,
    seal: usize,
    seal_bulk: usize,
}

fn crypto_completion_direction(completion: &CryptoCompletion) -> PacketMover2AeadDirection {
    match &completion.result {
        CryptoResult::Opened(_) | CryptoResult::Failed(CryptoFailureKind::Open) => {
            PacketMover2AeadDirection::Open
        }
        CryptoResult::Sealed(_)
        | CryptoResult::Outbound(_)
        | CryptoResult::Failed(CryptoFailureKind::Seal) => PacketMover2AeadDirection::Seal,
    }
}

fn count_completion_directions(completions: &[CryptoCompletion]) -> PacketMover2AeadDirectionCounts {
    let mut counts = PacketMover2AeadDirectionCounts {
        open: 0,
        open_bulk: 0,
        seal: 0,
        seal_bulk: 0,
    };
    for completion in completions {
        let is_bulk = completion.reservation.lane == Lane::Bulk;
        match crypto_completion_direction(completion) {
            PacketMover2AeadDirection::Open => {
                counts.open = counts.open.saturating_add(1);
                counts.open_bulk = counts.open_bulk.saturating_add(usize::from(is_bulk));
            }
            PacketMover2AeadDirection::Seal => {
                counts.seal = counts.seal.saturating_add(1);
                counts.seal_bulk = counts.seal_bulk.saturating_add(usize::from(is_bulk));
            }
        }
    }
    counts
}

#[derive(Debug)]
pub(crate) struct PacketMover2AeadWorkerPool {
    open_tx: Option<crossbeam_channel::Sender<PreparedCryptoJob>>,
    seal_tx: Option<crossbeam_channel::Sender<PreparedCryptoJob>>,
    completion_rx: Option<crossbeam_channel::Receiver<Vec<CryptoCompletion>>>,
    completion_notify: Arc<tokio::sync::Notify>,
    pending_completions: VecDeque<CryptoCompletion>,
    open_in_flight: Arc<std::sync::atomic::AtomicUsize>,
    seal_in_flight: Arc<std::sync::atomic::AtomicUsize>,
    open_bulk_in_flight: Arc<std::sync::atomic::AtomicUsize>,
    seal_bulk_in_flight: Arc<std::sync::atomic::AtomicUsize>,
    max_in_flight: usize,
    open_workers: Vec<std::thread::JoinHandle<()>>,
    seal_workers: Vec<std::thread::JoinHandle<()>>,
}

impl PacketMover2AeadWorkerPool {
    pub(crate) fn new(worker_count: usize, max_in_flight: usize) -> Self {
        let worker_count = worker_count.max(1);
        let max_in_flight = max_in_flight.max(1);
        let (completion_tx, completion_rx): (
            crossbeam_channel::Sender<Vec<CryptoCompletion>>,
            crossbeam_channel::Receiver<Vec<CryptoCompletion>>,
        ) = crossbeam_channel::bounded(max_in_flight);
        let completion_notify = Arc::new(tokio::sync::Notify::new());
        let open_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seal_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let open_bulk_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seal_bulk_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (open_tx, open_workers) = spawn_packet_mover2_aead_workers(
            PacketMover2AeadDirection::Open,
            worker_count,
            max_in_flight,
            completion_tx.clone(),
            Arc::clone(&completion_notify),
            Arc::clone(&open_in_flight),
            Arc::clone(&open_bulk_in_flight),
        );
        let (seal_tx, seal_workers) = spawn_packet_mover2_aead_workers(
            PacketMover2AeadDirection::Seal,
            worker_count,
            max_in_flight,
            completion_tx,
            Arc::clone(&completion_notify),
            Arc::clone(&seal_in_flight),
            Arc::clone(&seal_bulk_in_flight),
        );

        Self {
            open_tx: Some(open_tx),
            seal_tx: Some(seal_tx),
            completion_rx: Some(completion_rx),
            completion_notify,
            pending_completions: VecDeque::new(),
            open_in_flight,
            seal_in_flight,
            open_bulk_in_flight,
            seal_bulk_in_flight,
            max_in_flight,
            open_workers,
            seal_workers,
        }
    }

    pub(crate) fn completion_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.completion_notify)
    }

    fn drain_one_completion(
        &mut self,
        completion: CryptoCompletion,
        completions: &mut Vec<CryptoCompletion>,
    ) {
        let direction = crypto_completion_direction(&completion);
        let bulk_count = usize::from(completion.reservation.lane == Lane::Bulk);
        completions.push(completion);
        self.finish_drained_completions(direction, 1, bulk_count);
    }

    fn finish_drained_completions(
        &self,
        direction: PacketMover2AeadDirection,
        count: usize,
        bulk_count: usize,
    ) {
        let (in_flight, bulk_in_flight) = self.direction_counters(direction);
        in_flight.fetch_sub(count, std::sync::atomic::Ordering::AcqRel);
        if bulk_count > 0 {
            bulk_in_flight.fetch_sub(bulk_count, std::sync::atomic::Ordering::AcqRel);
        }
    }

    fn drain_completion_batch(
        &mut self,
        mut batch: Vec<CryptoCompletion>,
        limit: usize,
        out: &mut Vec<CryptoCompletion>,
    ) -> usize {
        let drained = batch.len().min(limit);
        if drained == 0 {
            self.pending_completions.extend(batch);
            return 0;
        }
        let pending = if drained < batch.len() {
            Some(batch.split_off(drained))
        } else {
            None
        };
        let drained_counts = count_completion_directions(&batch);
        if drained_counts.open > 0 {
            self.finish_drained_completions(
                PacketMover2AeadDirection::Open,
                drained_counts.open,
                drained_counts.open_bulk,
            );
        }
        if drained_counts.seal > 0 {
            self.finish_drained_completions(
                PacketMover2AeadDirection::Seal,
                drained_counts.seal,
                drained_counts.seal_bulk,
            );
        }
        out.extend(batch);
        if let Some(pending) = pending {
            self.pending_completions.extend(pending);
        }
        drained
    }

    fn direction_counters(
        &self,
        direction: PacketMover2AeadDirection,
    ) -> (
        &std::sync::atomic::AtomicUsize,
        &std::sync::atomic::AtomicUsize,
    ) {
        match direction {
            PacketMover2AeadDirection::Open => (&self.open_in_flight, &self.open_bulk_in_flight),
            PacketMover2AeadDirection::Seal => (&self.seal_in_flight, &self.seal_bulk_in_flight),
        }
    }

    fn direction_sender(
        &self,
        direction: PacketMover2AeadDirection,
    ) -> Option<&crossbeam_channel::Sender<PreparedCryptoJob>> {
        match direction {
            PacketMover2AeadDirection::Open => self.open_tx.as_ref(),
            PacketMover2AeadDirection::Seal => self.seal_tx.as_ref(),
        }
    }

    fn direction_worker_count(&self, direction: PacketMover2AeadDirection) -> usize {
        match direction {
            PacketMover2AeadDirection::Open => self.open_workers.len(),
            PacketMover2AeadDirection::Seal => self.seal_workers.len(),
        }
    }

    fn direction_capacity(&self, direction: PacketMover2AeadDirection) -> usize {
        if self.direction_sender(direction).is_none() {
            return 0;
        }
        let (in_flight, _) = self.direction_counters(direction);
        self.max_in_flight.saturating_sub(in_flight.load(std::sync::atomic::Ordering::Acquire))
    }

    fn direction_capacity_for_lane(&self, direction: PacketMover2AeadDirection, lane: Lane) -> usize {
        let total_available = self.direction_capacity(direction);
        if lane == Lane::Priority {
            return total_available;
        }
        let bulk_limit =
            self.max_in_flight
                .saturating_sub(packet_mover2_aead_worker_priority_reserve(
                    self.max_in_flight,
                ));
        let (_, bulk_in_flight) = self.direction_counters(direction);
        let bulk_in_flight = bulk_in_flight.load(std::sync::atomic::Ordering::Acquire);
        bulk_limit.saturating_sub(bulk_in_flight).min(total_available)
    }

    fn submit_prepared_job(
        &self,
        direction: PacketMover2AeadDirection,
        work: Vec<PreparedCryptoWork>,
        bulk_count: usize,
        completions: &mut Vec<CryptoCompletion>,
    ) -> bool {
        if work.is_empty() {
            return true;
        }
        let Some(work_tx) = self.direction_sender(direction) else {
            push_failed_prepared_work(work, completions);
            return false;
        };

        let chunk_len = work.len();
        let (in_flight, bulk_in_flight) = self.direction_counters(direction);
        in_flight.fetch_add(chunk_len, std::sync::atomic::Ordering::AcqRel);
        if bulk_count > 0 {
            bulk_in_flight.fetch_add(bulk_count, std::sync::atomic::Ordering::AcqRel);
        }
        let job = PreparedCryptoJob {
            queued_at: crate::perf_profile::stamp(),
            work,
            bulk_count,
        };
        match work_tx.try_send(job) {
            Ok(()) => true,
            Err(crossbeam_channel::TrySendError::Full(job))
            | Err(crossbeam_channel::TrySendError::Disconnected(job)) => {
                in_flight.fetch_sub(chunk_len, std::sync::atomic::Ordering::AcqRel);
                if bulk_count > 0 {
                    bulk_in_flight.fetch_sub(bulk_count, std::sync::atomic::Ordering::AcqRel);
                }
                push_failed_prepared_work(job.work, completions);
                false
            }
        }
    }
}

impl PacketMover2CryptoExecutor for PacketMover2AeadWorkerPool {
    fn available_capacity(&self) -> usize {
        self.available_open_capacity()
            .saturating_add(self.available_seal_capacity())
    }

    fn available_open_capacity(&self) -> usize {
        self.direction_capacity(PacketMover2AeadDirection::Open)
    }

    fn available_seal_capacity(&self) -> usize {
        self.direction_capacity(PacketMover2AeadDirection::Seal)
    }

    fn available_open_capacity_for_lane(&self, lane: Lane) -> usize {
        self.direction_capacity_for_lane(PacketMover2AeadDirection::Open, lane)
    }

    fn available_seal_capacity_for_lane(&self, lane: Lane) -> usize {
        self.direction_capacity_for_lane(PacketMover2AeadDirection::Seal, lane)
    }

    fn execute_prepared_chunk(
        &mut self,
        prepared: &mut Vec<PreparedCryptoWork>,
        completions: &mut Vec<CryptoCompletion>,
    ) -> usize {
        completions.clear();
        let count = prepared.len();
        if count == 0 {
            return 0;
        }

        let open_job_packets =
            packet_mover2_aead_worker_job_packets(count, self.direction_worker_count(PacketMover2AeadDirection::Open));
        let seal_job_packets =
            packet_mover2_aead_worker_job_packets(count, self.direction_worker_count(PacketMover2AeadDirection::Seal));
        let mut open_jobs =
            PreparedCryptoJobBuilder::new(PacketMover2AeadDirection::Open, open_job_packets);
        let mut seal_jobs =
            PreparedCryptoJobBuilder::new(PacketMover2AeadDirection::Seal, seal_job_packets);
        for work in prepared.drain(..) {
            match work {
                work @ PreparedCryptoWork::Open { .. } => {
                    open_jobs.push(self, work, completions);
                }
                work @ PreparedCryptoWork::Seal { .. } => {
                    seal_jobs.push(self, work, completions);
                }
                PreparedCryptoWork::Completed(completion) => completions.push(completion),
            }
        }
        open_jobs.flush(self, completions);
        seal_jobs.flush(self, completions);
        count
    }
}

impl PacketMover2CompletionSource for PacketMover2AeadWorkerPool {
    fn drain_completions_into(
        &mut self,
        limit: usize,
        completions: &mut Vec<CryptoCompletion>,
    ) -> usize {
        let mut drained = 0usize;
        while drained < limit {
            if let Some(completion) = self.pending_completions.pop_front() {
                self.drain_one_completion(completion, completions);
                drained += 1;
                continue;
            }

            let Some(completion_rx) = &self.completion_rx else {
                break;
            };
            match completion_rx.try_recv() {
                Ok(batch) => {
                    drained = drained.saturating_add(self.drain_completion_batch(
                        batch,
                        limit.saturating_sub(drained),
                        completions,
                    ));
                }
                Err(crossbeam_channel::TryRecvError::Empty)
                | Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        }
        drained
    }
}

fn spawn_packet_mover2_aead_workers(
    direction: PacketMover2AeadDirection,
    worker_count: usize,
    max_in_flight: usize,
    completion_tx: crossbeam_channel::Sender<Vec<CryptoCompletion>>,
    completion_notify: Arc<tokio::sync::Notify>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    bulk_in_flight: Arc<std::sync::atomic::AtomicUsize>,
) -> (
    crossbeam_channel::Sender<PreparedCryptoJob>,
    Vec<std::thread::JoinHandle<()>>,
) {
    let (work_tx, work_rx): (
        crossbeam_channel::Sender<PreparedCryptoJob>,
        crossbeam_channel::Receiver<PreparedCryptoJob>,
    ) = crossbeam_channel::bounded(max_in_flight);
    let mut workers = Vec::with_capacity(worker_count);
    for worker_idx in 0..worker_count {
        let work_rx = work_rx.clone();
        let completion_tx = completion_tx.clone();
        let completion_notify = Arc::clone(&completion_notify);
        let in_flight = Arc::clone(&in_flight);
        let bulk_in_flight = Arc::clone(&bulk_in_flight);
        workers.push(
            std::thread::Builder::new()
                .name(format!(
                    "pm2-aead-{}-{worker_idx}",
                    match direction {
                        PacketMover2AeadDirection::Open => "open",
                        PacketMover2AeadDirection::Seal => "seal",
                    }
                ))
                .spawn(move || {
                    while let Ok(job) = work_rx.recv() {
                        crate::perf_profile::record_since(
                            crate::perf_profile::Stage::PacketMover2AeadWorkerQueueWait,
                            job.queued_at,
                        );
                        let count = job.work.len();
                        let bulk_count = job.bulk_count;
                        let mut completions = Vec::with_capacity(count);
                        for work in job.work {
                            completions.push(work.execute());
                        }
                        if completion_tx.send(completions).is_err() {
                            in_flight.fetch_sub(count, std::sync::atomic::Ordering::AcqRel);
                            bulk_in_flight
                                .fetch_sub(bulk_count, std::sync::atomic::Ordering::AcqRel);
                            break;
                        }
                        completion_notify.notify_one();
                    }
                })
                .expect("spawn packet_mover2 AEAD worker"),
        );
    }
    (work_tx, workers)
}

fn push_failed_prepared_work(work: Vec<PreparedCryptoWork>, completions: &mut Vec<CryptoCompletion>) {
    for work in work {
        work.push_executor_failed_completions(completions);
    }
}

fn packet_mover2_aead_worker_priority_reserve(max_in_flight: usize) -> usize {
    max_in_flight
        .saturating_sub(PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS)
        .min(PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS)
}

fn packet_mover2_aead_worker_job_packets(work_count: usize, worker_count: usize) -> usize {
    let worker_count = worker_count.max(1);
    let divisor = worker_count.min(PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS);
    work_count.saturating_add(worker_count - 1) / divisor
}

impl Drop for PacketMover2AeadWorkerPool {
    fn drop(&mut self) {
        self.open_tx.take();
        self.seal_tx.take();
        self.completion_rx.take();
        for worker in self.open_workers.drain(..) {
            let _ = worker.join();
        }
        for worker in self.seal_workers.drain(..) {
            let _ = worker.join();
        }
    }
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
            Self::Completed(completion) => f
                .debug_tuple("PreparedCryptoWork::Completed")
                .field(completion)
                .finish(),
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

struct AeadOpenWork {
    work: CryptoWork,
    cipher: AeadKey,
    header: AeadHeader,
    ciphertext_offset: usize,
}

impl AeadOpenWork {
    fn from_crypto_work(work: CryptoWork, cipher: AeadKey) -> Result<Self, WirePreflightError> {
        let (header, ciphertext_offset, counter) = match work.packet.owner.protocol {
            PacketProtocol::Fmp => {
                let header = FmpWireHeader::parse(&work.packet.payload)?;
                (
                    AeadHeader::Fmp(header.header_bytes()),
                    header.ciphertext_offset(),
                    header.counter(),
                )
            }
            PacketProtocol::Fsp => {
                let header = FspWireHeader::parse(&work.packet.payload)?;
                (
                    AeadHeader::Fsp(header.header_bytes()),
                    header.ciphertext_offset(),
                    header.counter(),
                )
            }
        };
        if counter != work.packet.counter {
            return Err(WirePreflightError::CounterMismatch);
        }

        Ok(Self {
            work,
            cipher,
            header,
            ciphertext_offset,
        })
    }
    fn execute(self) -> CryptoCompletion {
        let mut work = self;
        let reservation = work.work.reservation;
        let target = work.work.packet.output;
        let header = work.header;
        let source_wire_len = work.work.packet.payload.len();
        let opened_len = match work.work.packet.payload.get_mut(work.ciphertext_offset..) {
            Some(ciphertext) => {
                let nonce = aead_nonce(reservation.counter);
                work.cipher
                    .open_in_place(nonce, Aad::from(header.as_aad()), ciphertext)
                    .map(|plaintext| plaintext.len())
                    .ok()
            }
            None => None,
        };

        let result = match opened_len {
            Some(plaintext_len) => {
                work.work
                    .packet
                    .payload
                    .truncate(work.ciphertext_offset + plaintext_len);
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
                    payload: work.work.packet.payload,
                })
            }
            None => CryptoResult::Failed(CryptoFailureKind::Open),
        };

        CryptoCompletion {
            reservation,
            result,
        }
    }
}

struct AeadSealWork {
    work: OutboundCryptoWork,
    cipher: AeadKey,
    post_seal: OutboundPostSeal,
    aad_len: usize,
    ciphertext_offset: usize,
}

impl AeadSealWork {
    fn from_outbound_work(
        mut work: OutboundCryptoWork,
        cipher: AeadKey,
    ) -> Result<Self, WireBuildError> {
        let inner_prefix = work.packet.crypto_plaintext_prefix(
            work.reservation.fmp_timestamp_ms,
            work.reservation.fsp_timestamp_ms,
        )?;
        let payload_len = u16::try_from(inner_prefix.len().saturating_add(work.packet.payload.len()))
            .map_err(|_| WireBuildError::PayloadTooLarge)?;
        let counter = work.reservation.counter;
        let (header, coord_prefix, ciphertext_offset) =
            match (work.packet.owner.protocol, work.packet.wire) {
            (
                PacketProtocol::Fmp,
                OutboundWire::Fmp {
                    receiver_idx,
                    flags,
                },
            ) => (
                AeadHeader::Fmp(build_fmp_established_header(
                    receiver_idx,
                    counter,
                    flags,
                    payload_len,
                )),
                Vec::new(),
                FMP_ESTABLISHED_HEADER_SIZE,
            ),
            (PacketProtocol::Fsp, OutboundWire::Fsp { flags }) => {
                let coord_prefix = std::mem::take(&mut work.packet.fsp_cleartext_prefix);
                validate_fsp_cleartext_prefix(flags, &coord_prefix)?;
                let ciphertext_offset = FSP_HEADER_SIZE + coord_prefix.len();
                (
                    AeadHeader::Fsp(build_fsp_established_header(counter, flags, payload_len)?),
                    coord_prefix,
                    ciphertext_offset,
                )
            }
            _ => return Err(WireBuildError::ProtocolMismatch),
        };

        let aad = header.as_aad();
        let aad_len = aad.len();
        let prefix_len = aad
            .len()
            .saturating_add(coord_prefix.len())
            .saturating_add(inner_prefix.len());
        if work.packet.payload.try_prepend_slices(
            &[aad, coord_prefix.as_slice(), inner_prefix.as_slice()],
            AEAD_TAG_SIZE,
        ) {
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketMover2SealInPlace);
        } else {
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketMover2SealAllocated);
            let plaintext = std::mem::take(&mut work.packet.payload);
            let mut payload = Vec::with_capacity(
                prefix_len
                    .saturating_add(plaintext.len())
                    .saturating_add(AEAD_TAG_SIZE),
            );
            payload.extend_from_slice(aad);
            payload.extend_from_slice(&coord_prefix);
            payload.extend_from_slice(&inner_prefix);
            payload.extend_from_slice(&plaintext);
            work.packet.payload = payload.into();
        }

        Ok(Self {
            post_seal: work.packet.post_seal,
            work,
            cipher,
            aad_len,
            ciphertext_offset,
        })
    }
    fn execute(self) -> CryptoCompletion {
        let mut work = self;
        let reservation = work.work.reservation;
        let tag = if work.aad_len <= work.ciphertext_offset
            && work.ciphertext_offset <= work.work.packet.payload.len()
        {
            let nonce = aead_nonce(reservation.counter);
            let (prefix, plaintext) = work
                .work
                .packet
                .payload
                .split_at_mut(work.ciphertext_offset);
            let Some(aad) = prefix.get(..work.aad_len) else {
                return CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Seal),
                };
            };
            work.cipher
                .seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext)
                .ok()
        } else {
            None
        };

        let result = match tag {
            Some(tag) => {
                work.work.packet.payload.extend_from_slice(tag.as_ref());
                match work.post_seal {
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
                        fsp_send_receipt: work.work.packet.fsp_send_receipt,
                        payload: work.work.packet.payload,
                    }),
                    OutboundPostSeal::FmpWrap(route) => {
                        let mut packet = route
                            .into_fmp_outbound(work.work.packet.class, work.work.packet.payload)
                            .with_fsp_send_receipt(PacketMover2FspSendReceipt::new(
                                reservation.owner,
                                reservation.counter,
                                reservation.fsp_timestamp_ms,
                            ));
                        if let Some(tick) = reservation.activity_tick {
                            packet = packet.with_activity_tick(tick);
                        }
                        CryptoResult::Outbound(packet)
                    }
                }
            }
            None => CryptoResult::Failed(CryptoFailureKind::Seal),
        };

        CryptoCompletion {
            reservation,
            result,
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
