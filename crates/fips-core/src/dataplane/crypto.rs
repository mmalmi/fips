pub(crate) enum PreparedCryptoWork {
    Open { work: CryptoWork, cipher: AeadKey },
    Seal { work: OutboundCryptoWork, cipher: AeadKey },
}

struct PreparedSealWork {
    work: OutboundCryptoWork,
    cipher: AeadKey,
}

impl PreparedSealWork {
    fn execute(self) -> CryptoCompletion {
        execute_seal_crypto_work(self.work, self.cipher)
    }

    fn failed_completion(self) -> CryptoCompletion {
        failed_crypto_completion(self.work.reservation, CryptoFailureKind::Seal)
    }

    fn lane(&self) -> Lane {
        self.work.reservation.lane
    }
}

const DATAPLANE_AEAD_WORKER_JOB_PACKETS: usize = 8;
const DATAPLANE_AEAD_WORKER_BATCH_PACKETS: usize = 128;

impl PreparedCryptoWork {
    pub(crate) fn open(work: CryptoWork, cipher: AeadKey) -> Self {
        Self::Open { work, cipher }
    }

    pub(crate) fn seal(work: OutboundCryptoWork, cipher: AeadKey) -> Self {
        Self::Seal { work, cipher }
    }

    #[cfg(test)]
    pub(crate) fn execute(self) -> CryptoCompletion {
        match self {
            Self::Open { work, cipher } => {
                let reservation = work.reservation.clone();
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::DataplaneAeadOpen,
                );
                match AeadOpenWork::from_crypto_work(work) {
                    Ok(work) => work.execute(&cipher),
                    Err(_) => failed_crypto_completion(reservation, CryptoFailureKind::Open),
                }
            }
            Self::Seal {
                work,
                cipher,
            } => execute_seal_crypto_work(work, cipher),
        }
    }

    fn lane(&self) -> Lane {
        match self {
            Self::Open { work, .. } => work.reservation.lane,
            Self::Seal { work, .. } => work.reservation.lane,
        }
    }
}

enum PreparedCryptoJob {
    OpenRun {
        queued_at: Option<crate::perf_profile::TraceStamp>,
        work: Vec<CryptoWork>,
        cipher: AeadKey,
        bulk_count: usize,
    },
    Seal {
        queued_at: Option<crate::perf_profile::TraceStamp>,
        work: Vec<PreparedSealWork>,
        bulk_count: usize,
    },
}

impl PreparedCryptoJob {
    fn open_run(work: Vec<CryptoWork>, cipher: AeadKey) -> Self {
        let bulk_count = dataplane_open_run_bulk_count(&work);
        Self::OpenRun {
            queued_at: crate::perf_profile::stamp(),
            work,
            cipher,
            bulk_count,
        }
    }

    fn seal(work: Vec<PreparedSealWork>, bulk_count: usize) -> Self {
        Self::Seal {
            queued_at: crate::perf_profile::stamp(),
            work,
            bulk_count,
        }
    }

    fn queued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        match self {
            Self::OpenRun { queued_at, .. } | Self::Seal { queued_at, .. } => *queued_at,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::OpenRun { work, .. } => work.len(),
            Self::Seal { work, .. } => work.len(),
        }
    }

    fn bulk_count(&self) -> usize {
        match self {
            Self::OpenRun { bulk_count, .. } | Self::Seal { bulk_count, .. } => *bulk_count,
        }
    }

    fn push_executor_failed_completions(self, completions: &mut Vec<CryptoCompletion>) {
        match self {
            Self::OpenRun { work, .. } => push_failed_open_work(work, completions),
            Self::Seal { work, .. } => push_failed_seal_work(work, completions),
        }
    }

    fn execute_completion_batches(self) -> Vec<CryptoCompletionBatch> {
        match self {
            Self::OpenRun { work, cipher, .. } => execute_open_run_job(work, cipher),
            Self::Seal { work, .. } => execute_seal_job(work),
        }
    }
}

struct PreparedOpenRunJobBuilder {
    job_packets: usize,
    work: Vec<CryptoWork>,
    cipher: Option<AeadKey>,
    next_order: Option<OrderToken>,
    closed: bool,
}

impl PreparedOpenRunJobBuilder {
    fn new() -> Self {
        Self {
            job_packets: DATAPLANE_AEAD_WORKER_BATCH_PACKETS,
            work: Vec::new(),
            cipher: None,
            next_order: None,
            closed: false,
        }
    }

    fn push(
        &mut self,
        pool: &DataplaneAeadWorkerPool,
        work: CryptoWork,
        cipher: AeadKey,
        completions: &mut Vec<CryptoCompletion>,
    ) {
        if self.closed {
            completions.push(failed_crypto_completion(
                work.reservation,
                CryptoFailureKind::Open,
            ));
            return;
        }
        if !self.matches_run(&work, &cipher) {
            self.flush(pool, completions);
            if self.closed {
                completions.push(failed_crypto_completion(
                    work.reservation,
                    CryptoFailureKind::Open,
                ));
                return;
            }
        }
        if self.work.len() >= self.job_packets {
            self.flush(pool, completions);
            if self.closed {
                completions.push(failed_crypto_completion(
                    work.reservation,
                    CryptoFailureKind::Open,
                ));
                return;
            }
        }
        self.next_order = Some(work.reservation.order.next());
        self.work.push(work);
        if self.cipher.is_none() {
            self.cipher = Some(cipher);
        }
    }

    fn flush(
        &mut self,
        pool: &DataplaneAeadWorkerPool,
        completions: &mut Vec<CryptoCompletion>,
    ) {
        if self.work.is_empty() || self.closed {
            return;
        }
        let next = Vec::with_capacity(self.job_packets);
        let work = std::mem::replace(&mut self.work, next);
        let cipher = self
            .cipher
            .take()
            .expect("open run cipher exists when work is non-empty");
        self.next_order = None;
        if !pool.submit_open_run_job(work, cipher, completions) {
            self.closed = true;
        }
    }

    fn matches_run(&self, work: &CryptoWork, cipher: &AeadKey) -> bool {
        let Some(first) = self.work.first() else {
            return true;
        };
        let Some(current_cipher) = self.cipher.as_ref() else {
            return true;
        };
        Arc::ptr_eq(current_cipher, cipher)
            && first.reservation.owner_shard() == work.reservation.owner_shard()
            && first.reservation.owner == work.reservation.owner
            && first.reservation.generation == work.reservation.generation
            && first.reservation.lane == work.reservation.lane
            && first.reservation.source_path == work.reservation.source_path
            && self.next_order == Some(work.reservation.order)
    }
}

struct PreparedSealJobBuilder {
    job_packets: usize,
    work: Vec<PreparedSealWork>,
    bulk_count: usize,
    closed: bool,
}

impl PreparedSealJobBuilder {
    fn new() -> Self {
        Self {
            job_packets: DATAPLANE_AEAD_WORKER_BATCH_PACKETS,
            work: Vec::new(),
            bulk_count: 0,
            closed: false,
        }
    }

    fn push(
        &mut self,
        pool: &DataplaneAeadWorkerPool,
        work: PreparedSealWork,
        completions: &mut Vec<CryptoCompletion>,
    ) {
        if self.closed {
            completions.push(work.failed_completion());
            return;
        }
        if work.lane() == Lane::Bulk {
            self.bulk_count = self.bulk_count.saturating_add(1);
        }
        if self.work.capacity() == 0 {
            self.work.reserve_exact(self.job_packets);
        }
        self.work.push(work);
        if self.work.len() >= self.job_packets {
            self.flush(pool, completions);
        }
    }

    fn flush(
        &mut self,
        pool: &DataplaneAeadWorkerPool,
        completions: &mut Vec<CryptoCompletion>,
    ) {
        if self.work.is_empty() || self.closed {
            return;
        }
        let next = Vec::with_capacity(self.job_packets);
        let work = std::mem::replace(&mut self.work, next);
        let bulk_count = std::mem::take(&mut self.bulk_count);
        if !pool.submit_seal_job(work, bulk_count, completions) {
            self.closed = true;
        }
    }
}

pub(crate) trait DataplaneCryptoExecutor {
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
enum DataplaneAeadDirection {
    Open,
    Seal,
}

#[derive(Debug)]
pub(crate) struct DataplaneAeadWorkerPool {
    open_tx: Option<crossbeam_channel::Sender<PreparedCryptoJob>>,
    seal_tx: Option<crossbeam_channel::Sender<PreparedCryptoJob>>,
    completion_rx: Option<crossbeam_channel::Receiver<Vec<CryptoCompletionBatch>>>,
    completion_notify: Arc<tokio::sync::Notify>,
    pending_completion_batches: VecDeque<CryptoCompletionBatch>,
    open_in_flight: Arc<std::sync::atomic::AtomicUsize>,
    seal_in_flight: Arc<std::sync::atomic::AtomicUsize>,
    open_bulk_in_flight: Arc<std::sync::atomic::AtomicUsize>,
    seal_bulk_in_flight: Arc<std::sync::atomic::AtomicUsize>,
    max_in_flight: usize,
    open_workers: Vec<std::thread::JoinHandle<()>>,
    seal_workers: Vec<std::thread::JoinHandle<()>>,
}

impl DataplaneAeadWorkerPool {
    pub(crate) fn new(worker_count: usize, max_in_flight: usize) -> Self {
        let worker_count = worker_count.max(1);
        let max_in_flight = max_in_flight.max(1);
        let (completion_tx, completion_rx): (
            crossbeam_channel::Sender<Vec<CryptoCompletionBatch>>,
            crossbeam_channel::Receiver<Vec<CryptoCompletionBatch>>,
        ) = crossbeam_channel::bounded(max_in_flight.saturating_mul(worker_count));
        let completion_notify = Arc::new(tokio::sync::Notify::new());
        let open_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seal_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let open_bulk_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seal_bulk_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (open_tx, open_workers) = spawn_dataplane_aead_workers(
            DataplaneAeadDirection::Open,
            worker_count,
            max_in_flight,
            completion_tx.clone(),
            Arc::clone(&completion_notify),
            Arc::clone(&open_in_flight),
            Arc::clone(&open_bulk_in_flight),
        );
        let (seal_tx, seal_workers) = spawn_dataplane_aead_workers(
            DataplaneAeadDirection::Seal,
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
            pending_completion_batches: VecDeque::new(),
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

    pub(crate) fn has_ready_completions(&self) -> bool {
        !self.pending_completion_batches.is_empty()
            || self
                .completion_rx
                .as_ref()
                .is_some_and(|completion_rx| !completion_rx.is_empty())
    }

    pub(crate) fn record_perf_depths(&self) {
        if !crate::perf_profile::enabled() {
            return;
        }
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadOpenInFlight,
            self.open_in_flight
                .load(std::sync::atomic::Ordering::Acquire) as u64,
        );
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadSealInFlight,
            self.seal_in_flight
                .load(std::sync::atomic::Ordering::Acquire) as u64,
        );
        let pending_completion_depth = self
            .pending_completion_batches
            .iter()
            .map(CryptoCompletionBatch::len)
            .sum::<usize>();
        let pending_completion_batches = self.pending_completion_batches.len();
        let rx_queued_messages = self.completion_rx.as_ref().map_or(0, |rx| rx.len());
        let completion_depth = pending_completion_depth.saturating_add(rx_queued_messages);
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadCompletionQueueDepth,
            completion_depth as u64,
        );
        crate::perf_profile::record_dataplane_aead_completion_backlog(
            rx_queued_messages,
            pending_completion_batches,
            pending_completion_depth,
        );
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadOpenQueueDepth,
            self.open_tx.as_ref().map_or(0, |tx| tx.len()) as u64,
        );
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadSealQueueDepth,
            self.seal_tx.as_ref().map_or(0, |tx| tx.len()) as u64,
        );
    }

    fn finish_drained_completions(
        &self,
        direction: DataplaneAeadDirection,
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
        mut batch: CryptoCompletionBatch,
        limit: usize,
        push_batch: &mut impl FnMut(CryptoCompletionBatch),
    ) -> (usize, Option<CryptoCompletionBatch>) {
        crate::perf_profile::record_dataplane_aead_completion_batch(batch.len());
        let drained = batch.len().min(limit);
        if drained == 0 {
            return (0, Some(batch));
        }
        let pending = if drained < batch.len() {
            let pending = batch.split_off(drained);
            crate::perf_profile::record_dataplane_aead_completion_split(pending.len());
            Some(pending)
        } else {
            None
        };
        let direction = dataplane_aead_direction_for_completion_source(batch.source());
        let bulk_count = if batch.lane() == Lane::Bulk { drained } else { 0 };
        self.finish_drained_completions(direction, drained, bulk_count);
        push_batch(batch);
        (drained, pending)
    }

    fn drain_completion_batches_with(
        &mut self,
        limit: usize,
        mut push_batch: impl FnMut(CryptoCompletionBatch),
    ) -> usize {
        let mut drained = 0usize;
        let mut empty_polls = 0usize;
        while drained < limit {
            if let Some(batch) = self.pending_completion_batches.pop_front() {
                let (got, pending) = self.drain_completion_batch(
                    batch,
                    limit.saturating_sub(drained),
                    &mut push_batch,
                );
                drained = drained.saturating_add(got);
                if let Some(pending) = pending {
                    self.pending_completion_batches.push_front(pending);
                    break;
                }
                continue;
            }

            let Some(completion_rx) = self.completion_rx.as_ref() else {
                break;
            };
            let received = completion_rx.try_recv();
            match received {
                Ok(mut batches) => {
                    let mut batches = batches.drain(..);
                    while let Some(batch) = batches.next() {
                        if drained >= limit {
                            self.pending_completion_batches.push_back(batch);
                            self.pending_completion_batches.extend(batches);
                            break;
                        }
                        let (got, pending) = self.drain_completion_batch(
                            batch,
                            limit.saturating_sub(drained),
                            &mut push_batch,
                        );
                        drained = drained.saturating_add(got);
                        if let Some(pending) = pending {
                            self.pending_completion_batches.push_back(pending);
                            self.pending_completion_batches.extend(batches);
                            break;
                        }
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {
                    empty_polls = empty_polls.saturating_add(1);
                    break;
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        }
        crate::perf_profile::record_dataplane_aead_completion_empty_polls(empty_polls);
        drained
    }

    fn direction_counters(
        &self,
        direction: DataplaneAeadDirection,
    ) -> (
        &std::sync::atomic::AtomicUsize,
        &std::sync::atomic::AtomicUsize,
    ) {
        match direction {
            DataplaneAeadDirection::Open => (&self.open_in_flight, &self.open_bulk_in_flight),
            DataplaneAeadDirection::Seal => (&self.seal_in_flight, &self.seal_bulk_in_flight),
        }
    }

    fn direction_has_sender(&self, direction: DataplaneAeadDirection) -> bool {
        match direction {
            DataplaneAeadDirection::Open => self.open_tx.is_some(),
            DataplaneAeadDirection::Seal => self.seal_tx.is_some(),
        }
    }

    fn direction_capacity(&self, direction: DataplaneAeadDirection) -> usize {
        if !self.direction_has_sender(direction) {
            return 0;
        }
        let (in_flight, _) = self.direction_counters(direction);
        self.max_in_flight.saturating_sub(in_flight.load(std::sync::atomic::Ordering::Acquire))
    }

    fn direction_capacity_for_lane(&self, direction: DataplaneAeadDirection, lane: Lane) -> usize {
        let total_available = self.direction_capacity(direction);
        if lane == Lane::Priority {
            return total_available;
        }
        let bulk_limit =
            self.max_in_flight
                .saturating_sub(dataplane_aead_worker_priority_reserve(
                    self.max_in_flight,
                ));
        let (_, bulk_in_flight) = self.direction_counters(direction);
        let bulk_in_flight = bulk_in_flight.load(std::sync::atomic::Ordering::Acquire);
        bulk_limit.saturating_sub(bulk_in_flight).min(total_available)
    }

    fn submit_seal_job(
        &self,
        work: Vec<PreparedSealWork>,
        bulk_count: usize,
        completions: &mut Vec<CryptoCompletion>,
    ) -> bool {
        if work.is_empty() {
            return true;
        }
        let Some(work_tx) = self.seal_tx.as_ref() else {
            push_failed_seal_work(work, completions);
            return false;
        };

        let job = PreparedCryptoJob::seal(work, bulk_count);
        self.submit_job(work_tx, DataplaneAeadDirection::Seal, job, completions)
    }

    fn submit_open_run_job(
        &self,
        work: Vec<CryptoWork>,
        cipher: AeadKey,
        completions: &mut Vec<CryptoCompletion>,
    ) -> bool {
        if work.is_empty() {
            return true;
        }
        let Some(work_tx) = self.open_tx.as_ref() else {
            push_failed_open_work(work, completions);
            return false;
        };

        let job = PreparedCryptoJob::open_run(work, cipher);
        self.submit_job(work_tx, DataplaneAeadDirection::Open, job, completions)
    }

    fn submit_job(
        &self,
        work_tx: &crossbeam_channel::Sender<PreparedCryptoJob>,
        direction: DataplaneAeadDirection,
        job: PreparedCryptoJob,
        completions: &mut Vec<CryptoCompletion>,
    ) -> bool {
        let chunk_len = job.len();
        let bulk_count = job.bulk_count();
        let (in_flight, bulk_in_flight) = self.direction_counters(direction);
        in_flight.fetch_add(chunk_len, std::sync::atomic::Ordering::AcqRel);
        if bulk_count > 0 {
            bulk_in_flight.fetch_add(bulk_count, std::sync::atomic::Ordering::AcqRel);
        }
        match work_tx.try_send(job) {
            Ok(()) => {
                crate::perf_profile::record_dataplane_aead_prepared_job(chunk_len);
                true
            }
            Err(crossbeam_channel::TrySendError::Full(job))
            | Err(crossbeam_channel::TrySendError::Disconnected(job)) => {
                in_flight.fetch_sub(chunk_len, std::sync::atomic::Ordering::AcqRel);
                if bulk_count > 0 {
                    bulk_in_flight.fetch_sub(bulk_count, std::sync::atomic::Ordering::AcqRel);
                }
                job.push_executor_failed_completions(completions);
                false
            }
        }
    }
}

impl DataplaneCryptoExecutor for DataplaneAeadWorkerPool {
    fn available_capacity(&self) -> usize {
        self.available_open_capacity()
            .saturating_add(self.available_seal_capacity())
    }

    fn available_open_capacity(&self) -> usize {
        self.direction_capacity(DataplaneAeadDirection::Open)
    }

    fn available_seal_capacity(&self) -> usize {
        self.direction_capacity(DataplaneAeadDirection::Seal)
    }

    fn available_open_capacity_for_lane(&self, lane: Lane) -> usize {
        self.direction_capacity_for_lane(DataplaneAeadDirection::Open, lane)
    }

    fn available_seal_capacity_for_lane(&self, lane: Lane) -> usize {
        self.direction_capacity_for_lane(DataplaneAeadDirection::Seal, lane)
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

        let mut open_jobs = PreparedOpenRunJobBuilder::new();
        let mut seal_jobs = PreparedSealJobBuilder::new();
        for work in prepared.drain(..) {
            match work {
                PreparedCryptoWork::Open { work, cipher } => {
                    open_jobs.push(self, work, cipher, completions);
                }
                PreparedCryptoWork::Seal { work, cipher } => {
                    seal_jobs.push(self, PreparedSealWork { work, cipher }, completions);
                }
            }
        }
        open_jobs.flush(self, completions);
        seal_jobs.flush(self, completions);
        count
    }
}

impl DataplaneCompletionSource for DataplaneAeadWorkerPool {
    fn drain_completion_batches_into_sink<S>(
        &mut self,
        limit: usize,
        sink: &mut S,
    ) -> usize
    where
        S: DataplaneCompletionSink,
    {
        self.drain_completion_batches_with(limit, |batch| {
            sink.push_completion_batch(batch);
        })
    }
}

fn spawn_dataplane_aead_workers(
    direction: DataplaneAeadDirection,
    worker_count: usize,
    max_in_flight: usize,
    completion_tx: crossbeam_channel::Sender<Vec<CryptoCompletionBatch>>,
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
        workers.push(spawn_dataplane_aead_worker_thread(
            direction,
            worker_idx,
            work_rx,
            completion_tx.clone(),
            Arc::clone(&completion_notify),
            Arc::clone(&in_flight),
            Arc::clone(&bulk_in_flight),
        ));
    }
    (work_tx, workers)
}

fn spawn_dataplane_aead_worker_thread(
    direction: DataplaneAeadDirection,
    worker_idx: usize,
    work_rx: crossbeam_channel::Receiver<PreparedCryptoJob>,
    completion_tx: crossbeam_channel::Sender<Vec<CryptoCompletionBatch>>,
    completion_notify: Arc<tokio::sync::Notify>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    bulk_in_flight: Arc<std::sync::atomic::AtomicUsize>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!(
            "dataplane-aead-{}-{worker_idx}",
            match direction {
                DataplaneAeadDirection::Open => "open",
                DataplaneAeadDirection::Seal => "seal",
            }
        ))
        .spawn(move || {
            while let Ok(job) = work_rx.recv() {
                crate::perf_profile::record_since(
                    crate::perf_profile::Stage::DataplaneAeadWorkerQueueWait,
                    job.queued_at(),
                );
                let count = job.len();
                let bulk_count = job.bulk_count();
                let completions = job.execute_completion_batches();
                if send_completion_batches(completions, &completion_tx).is_err() {
                    in_flight.fetch_sub(count, std::sync::atomic::Ordering::AcqRel);
                    bulk_in_flight.fetch_sub(bulk_count, std::sync::atomic::Ordering::AcqRel);
                    break;
                }
                completion_notify.notify_one();
            }
        })
        .expect("spawn dataplane AEAD worker")
}

fn send_completion_batches(
    batches: Vec<CryptoCompletionBatch>,
    completion_tx: &crossbeam_channel::Sender<Vec<CryptoCompletionBatch>>,
) -> Result<(), ()> {
    if batches.is_empty() {
        return Ok(());
    }

    if crate::perf_profile::enabled() {
        let completion_batch_count = batches.len();
        let completion_packet_count = batches
            .iter()
            .map(CryptoCompletionBatch::len)
            .sum::<usize>();
        crate::perf_profile::record_dataplane_aead_completion_send(
            1,
            completion_batch_count,
            completion_packet_count,
        );
    }
    completion_tx.send(batches).map_err(|_| ())?;
    Ok(())
}

fn dataplane_aead_direction_for_completion_source(
    source: CryptoCompletionSource,
) -> DataplaneAeadDirection {
    match source {
        CryptoCompletionSource::Open => DataplaneAeadDirection::Open,
        CryptoCompletionSource::Seal => DataplaneAeadDirection::Seal,
    }
}

fn push_failed_seal_work(work: Vec<PreparedSealWork>, completions: &mut Vec<CryptoCompletion>) {
    for work in work {
        completions.push(work.failed_completion());
    }
}

fn push_failed_open_work(work: Vec<CryptoWork>, completions: &mut Vec<CryptoCompletion>) {
    for work in work {
        completions.push(failed_crypto_completion(
            work.reservation,
            CryptoFailureKind::Open,
        ));
    }
}

fn execute_open_run_job(work: Vec<CryptoWork>, cipher: AeadKey) -> Vec<CryptoCompletionBatch> {
    if work.is_empty() {
        return Vec::new();
    }
    let _timer =
        crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneAeadOpen);
    let mut completions = Vec::with_capacity(work.len());
    for work in work {
        completions.push(execute_open_crypto_work(work, &cipher));
    }
    CryptoCompletionBatch::from_completion_run(completions)
        .into_iter()
        .collect()
}

fn execute_seal_job(work: Vec<PreparedSealWork>) -> Vec<CryptoCompletionBatch> {
    if work.is_empty() {
        return Vec::new();
    }
    let mut completions = Vec::with_capacity(work.len());
    for work in work {
        CryptoCompletionBatch::push_grouped(work.execute(), &mut completions);
    }
    completions
}

fn dataplane_open_run_bulk_count(work: &[CryptoWork]) -> usize {
    match work.first() {
        Some(first) if first.reservation.lane == Lane::Bulk => work.len(),
        Some(_) | None => 0,
    }
}

fn dataplane_aead_worker_priority_reserve(max_in_flight: usize) -> usize {
    max_in_flight
        .saturating_sub(DATAPLANE_AEAD_WORKER_JOB_PACKETS)
        .min(DATAPLANE_AEAD_WORKER_JOB_PACKETS)
}

impl Drop for DataplaneAeadWorkerPool {
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
    header: AeadHeader,
    ciphertext_offset: usize,
}

fn execute_open_crypto_work(work: CryptoWork, cipher: &LessSafeKey) -> CryptoCompletion {
    let reservation = work.reservation.clone();
    match AeadOpenWork::from_crypto_work(work) {
        Ok(work) => work.execute(cipher),
        Err(_) => failed_crypto_completion(reservation, CryptoFailureKind::Open),
    }
}

impl AeadOpenWork {
    fn from_crypto_work(work: CryptoWork) -> Result<Self, WirePreflightError> {
        let (header, ciphertext_offset, counter) = match work.packet.owner.protocol {
            PacketProtocol::Fmp => {
                let header = FmpWireHeader::parse(work.packet.payload.as_slice())?;
                (
                    AeadHeader::Fmp(header.header_bytes()),
                    header.ciphertext_offset(),
                    header.counter(),
                )
            }
            PacketProtocol::Fsp => {
                let header = FspWireHeader::parse(work.packet.payload.as_slice())?;
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
            header,
            ciphertext_offset,
        })
    }
    fn execute(self, cipher: &LessSafeKey) -> CryptoCompletion {
        let mut work = self;
        let reservation = work.work.reservation;
        let target = work.work.packet.output;
        let header = work.header;
        let source_wire_len = work.work.packet.payload.len();
        let opened_len = match work
            .work
            .packet
            .payload
            .as_mut_slice()
            .get_mut(work.ciphertext_offset..)
        {
            Some(ciphertext) => {
                let nonce = aead_nonce(reservation.counter);
                cipher
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
                    send_token: reservation.send_token,
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

fn execute_seal_crypto_work(work: OutboundCryptoWork, cipher: AeadKey) -> CryptoCompletion {
    let reservation = work.reservation.clone();
    let _timer = crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneAeadSeal);
    match AeadSealWork::from_outbound_work(work, cipher) {
        Ok(work) => work.execute(),
        Err(_) => failed_crypto_completion(reservation, CryptoFailureKind::Seal),
    }
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
            crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneSealInPlace);
        } else {
            crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneSealAllocated);
            let plaintext = std::mem::take(&mut work.packet.payload);
            let mut payload = Vec::with_capacity(
                prefix_len
                    .saturating_add(plaintext.len())
                    .saturating_add(AEAD_TAG_SIZE),
            );
            payload.extend_from_slice(aad);
            payload.extend_from_slice(&coord_prefix);
            payload.extend_from_slice(&inner_prefix);
            payload.extend_from_slice(plaintext.as_slice());
            work.packet.payload = PacketBuffer::new(payload);
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
                .as_mut_slice()
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
                        send_token: reservation.send_token,
                        payload: work.work.packet.payload,
                    }),
                    OutboundPostSeal::FmpWrap(route) => {
                        let mut packet = route
                            .into_fmp_outbound(work.work.packet.class, work.work.packet.payload)
                            .with_fsp_send_receipt(DataplaneFspSendReceipt {
                                owner: reservation.owner,
                                counter: reservation.counter,
                            });
                        if let Some(send_token) = work.work.packet.send_token {
                            packet = packet.with_send_token(send_token);
                        }
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
