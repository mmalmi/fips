/// Handle to the encrypt worker pool.
///
/// Workers are **dedicated `std::thread`s** with bounded queues between
/// them and the rx_loop. The earlier tokio-task version of this worker
/// pool was the right shape, but every cross-runtime
/// wake (rx_loop's tokio task → tokio worker task) costs the tokio
/// scheduler an internal hop. Replacing the worker side with a sync
/// OS thread cuts the dispatch round-trip to the platform minimum —
/// same pattern boringtun uses for its main loop.
///
/// **Ordering: hash-by-send-target** so single-flow TCP keeps its
/// FIFO ordering (round-robin caused 8000 retransmits in an earlier
/// experiment — see the git log for the 56e0ca8 fix). Multi-peer /
/// multi-flow benches still get parallelism since different
/// send targets hash to different workers.
#[derive(Clone)]
pub(crate) struct EncryptWorkerPool {
    senders: Arc<[WorkerSender]>,
    #[cfg(target_os = "linux")]
    linux_wg_batch_senders: Arc<[Sender<LinuxWgEncryptBatch>]>,
    #[cfg(target_os = "linux")]
    linux_wg_batch_flows: Arc<LinuxWgBatchSendFlows>,
    #[cfg(target_os = "linux")]
    next_wg_batch_worker: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(target_os = "macos")]
    macos_senders: Arc<MacSequencedSendFlows>,
    #[cfg(target_os = "macos")]
    next_worker: Arc<std::sync::atomic::AtomicUsize>,
}

impl EncryptWorkerPool {
    /// Spawn `n` worker **OS threads** and return a handle that
    /// dispatches jobs hash-by-send-target to them. The workers exit
    /// when all senders for their channel are dropped (i.e. when the
    /// returned `EncryptWorkerPool` and all clones go away).
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let worker_channel_cap = worker_channel_cap();
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            #[cfg(target_os = "macos")]
            {
                let (tx, rx) = mac_worker_channel(worker_channel_cap);
                std::thread::Builder::new()
                    .name(format!("fips-encrypt-{i}"))
                    .spawn(move || run_worker_macos(i, rx))
                    .expect("failed to spawn fips-encrypt OS thread");
                senders.push(tx);
            }
            #[cfg(not(target_os = "macos"))]
            {
                let (tx, rx) = fair_worker_channel(
                    worker_channel_cap.saturating_mul(4).max(1),
                    worker_channel_cap,
                    WORKER_FAIR_QUANTUM_BYTES,
                );
                std::thread::Builder::new()
                    .name(format!("fips-encrypt-{i}"))
                    .spawn(move || run_worker(i, rx))
                    .expect("failed to spawn fips-encrypt OS thread");
                senders.push(tx);
            }
        }
        #[cfg(target_os = "linux")]
        let linux_wg_batch_senders = {
            let mut batch_senders = Vec::with_capacity(n);
            for i in 0..n {
                let (tx, rx) = bounded(LINUX_WG_BATCH_WORKER_CHANNEL_CAP);
                std::thread::Builder::new()
                    .name(format!("fips-linux-wg-encrypt-{i}"))
                    .spawn(move || run_linux_wg_batch_worker(
                        i,
                        rx,
                        DEFAULT_LINUX_WG_BATCH_CHUNK_SIZE,
                    ))
                    .expect("failed to spawn fips Linux WG-batch encrypt thread");
                batch_senders.push(tx);
            }
            Arc::<[Sender<LinuxWgEncryptBatch>]>::from(batch_senders)
        };
        Self {
            senders: senders.into(),
            #[cfg(target_os = "linux")]
            linux_wg_batch_senders,
            #[cfg(target_os = "linux")]
            linux_wg_batch_flows: Arc::new(LinuxWgBatchSendFlows::default()),
            #[cfg(target_os = "linux")]
            next_wg_batch_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(target_os = "macos")]
            macos_senders: Arc::new(MacSequencedSendFlows::default()),
            #[cfg(target_os = "macos")]
            next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Dispatch a job to the worker that owns its send-target flow.
    /// The hash is over `(socket fd, connected fd, dest_addr)` so every
    /// packet for one exact kernel send target lands on the same worker and
    /// stays in order — required for TCP's fast-retransmit logic above to
    /// behave on a single-flow run. Fire-and-forget — the worker
    /// handles send errors itself via stats counters.
    ///
    /// Uses `try_send` for the common uncontended case. Control/liveness jobs
    /// may still block if their reserve is exhausted, but a full bulk lane is
    /// treated like a congested network queue: drop the newly admitted bulk
    /// packet instead of blocking the node rx_loop that must keep ACKs,
    /// heartbeats, and route measurements moving.
    pub fn dispatch(&self, job: FmpSendJob) {
        let started_at = encrypt_worker_dispatch_timer();
        self.dispatch_unmeasured(job);
        record_encrypt_worker_dispatch(started_at, 1);
    }

    pub(crate) fn dispatch_bulk_batch(&self, jobs: Vec<FmpSendJob>) {
        #[cfg(target_os = "linux")]
        let mut jobs = jobs;
        #[cfg(not(target_os = "linux"))]
        let jobs = jobs;
        let count = jobs.len();
        if count == 0 {
            return;
        }
        let started_at = encrypt_worker_dispatch_timer();

        #[cfg(target_os = "linux")]
        {
            match self.dispatch_linux_wg_bulk_batch_unmeasured(jobs) {
                Ok(()) => {
                    record_encrypt_worker_dispatch(started_at, count);
                    return;
                }
                Err(returned_jobs) => {
                    jobs = returned_jobs;
                }
            }
        }

        for job in jobs {
            self.dispatch_unmeasured(job);
        }
        record_encrypt_worker_dispatch(started_at, count);
    }

    /// Dispatch bulk jobs after the caller has committed node-side
    /// bookkeeping. Unlike [`Self::dispatch_bulk_batch`], this path never
    /// turns a full bulk worker queue into a silent packet drop: it applies
    /// backpressure to the app-side bulk mover and lets the upstream bulk queue
    /// slow/drop before control, rekey, and liveness work lose service.
    pub(crate) fn dispatch_bulk_batch_blocking(&self, jobs: Vec<FmpSendJob>) -> bool {
        #[cfg(target_os = "linux")]
        let mut jobs = jobs;
        #[cfg(not(target_os = "linux"))]
        let jobs = jobs;
        let count = jobs.len();
        if count == 0 {
            return true;
        }
        debug_assert!(
            jobs.iter().all(|job| job.bulk_endpoint_data),
            "committed bulk dispatch should only receive bulk endpoint data"
        );
        let started_at = encrypt_worker_dispatch_timer();

        #[cfg(target_os = "linux")]
        {
            match self.dispatch_linux_wg_bulk_batch_blocking_unmeasured(jobs) {
                Ok(all_enqueued) => {
                    record_encrypt_worker_dispatch(started_at, count);
                    return all_enqueued;
                }
                Err(returned_jobs) => {
                    jobs = returned_jobs;
                }
            }
        }

        let mut all_enqueued = true;
        for job in jobs {
            if !self.dispatch_unmeasured_blocking(job) {
                all_enqueued = false;
            }
        }
        record_encrypt_worker_dispatch(started_at, count);
        all_enqueued
    }

    fn dispatch_unmeasured(&self, job: FmpSendJob) {
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping job");
            return;
        }
        let (idx, job) = self.prepare_dispatch(job);
        crate::perf_profile::record_fmp_worker_dispatch_target(idx, job.endpoint_flow_keyed());
        self.dispatch_to_worker(idx, job);
    }

    fn dispatch_unmeasured_blocking(&self, job: FmpSendJob) -> bool {
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping committed bulk job");
            return false;
        }
        let (idx, job) = self.prepare_dispatch(job);
        crate::perf_profile::record_fmp_worker_dispatch_target(idx, job.endpoint_flow_keyed());
        self.dispatch_to_worker_blocking(idx, job)
    }

    #[cfg(target_os = "macos")]
    fn prepare_dispatch(&self, job: FmpSendJob) -> (usize, QueuedFmpSendJob) {
        if !macos_ordered_sender_enabled() {
            use std::hash::{Hash, Hasher};

            let queued = QueuedFmpSendJob::direct(job);
            let key = queued.target_key();
            let mut h = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut h);
            let idx = (h.finish() as usize) % self.senders.len();
            return (idx, queued);
        }

        // Darwin has no sendmmsg/UDP_GSO equivalent in the standard UDP
        // path, and high-rate Wi-Fi sends regularly block in ENOBUFS. Keep
        // nonce assignment in rx_loop, spread FMP AEAD over the worker pool,
        // then serialize already-encrypted packets through one sender per
        // kernel 5-tuple. This mirrors wireguard-go's
        // route/nonce -> parallel encrypt -> sequential transmit shape.
        let flow = self.macos_senders.flow_for(&job);
        let ticket = self
            .next_worker
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            / macos_worker_stride();
        let idx = ticket % self.senders.len();
        (idx, QueuedFmpSendJob::macos_sequenced(job, flow))
    }

    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    fn prepare_dispatch(&self, job: FmpSendJob) -> (usize, QueuedFmpSendJob) {
        let queued = QueuedFmpSendJob::direct(job);
        let idx = (send_dispatch_fast_hash(&queued.dispatch_key()) as usize) % self.senders.len();
        (idx, queued)
    }

    #[cfg(target_os = "linux")]
    fn prepare_dispatch(&self, job: FmpSendJob) -> (usize, QueuedFmpSendJob) {
        let queued = QueuedFmpSendJob::direct(job);
        let idx = (send_dispatch_fast_hash(&queued.dispatch_key()) as usize) % self.senders.len();
        (idx, queued)
    }

    #[cfg(target_os = "macos")]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) {
        match self.senders[idx].try_push(job) {
            Ok(()) => {}
            Err(MacWorkerTryPushError::Full(job)) => {
                record_encrypt_worker_queue_full(job.queue_lane());
                if job.queue_lane() == EncryptWorkerLane::Bulk {
                    record_encrypt_worker_backpressure_drop(idx);
                    (*job).discard_without_send();
                    return;
                }
                static FULL_COUNT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        full_events = n + 1,
                        "EncryptWorker channel full; applying outbound backpressure"
                    );
                }
                if let Err(MacWorkerPushError) = self.senders[idx].push_blocking(*job) {
                    debug!(worker = idx, "EncryptWorker thread gone; dropping job");
                }
            }
            Err(MacWorkerTryPushError::Closed) => {
                debug!(worker = idx, "EncryptWorker thread gone; dropping job");
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn dispatch_to_worker_blocking(&self, idx: usize, job: QueuedFmpSendJob) -> bool {
        let lane = job.queue_lane();
        match self.senders[idx].push_blocking(job) {
            Ok(()) => true,
            Err(MacWorkerPushError) => {
                if lane == EncryptWorkerLane::Bulk {
                    record_encrypt_worker_backpressure_drop(idx);
                }
                debug!(worker = idx, "EncryptWorker thread gone; dropping committed bulk job");
                false
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) {
        let sender = &self.senders[idx];
        match sender.try_push(job) {
            Ok(()) => {}
            Err(FairWorkerTryPushError::Full(job)) => {
                record_encrypt_worker_queue_full(job.queue_lane());
                if job.queue_lane() == EncryptWorkerLane::Bulk {
                    record_encrypt_worker_backpressure_drop(idx);
                    (*job).discard_without_send();
                    return;
                }
                static FULL_COUNT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        full_events = n + 1,
                        "EncryptWorker channel full; applying outbound backpressure"
                    );
                }
                if let Err(FairWorkerPushError) = sender.push_blocking(*job) {
                    debug!(worker = idx, "EncryptWorker thread gone; dropping job");
                }
            }
            Err(FairWorkerTryPushError::Closed) => {
                debug!(worker = idx, "EncryptWorker thread gone; dropping job");
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn dispatch_to_worker_blocking(&self, idx: usize, job: QueuedFmpSendJob) -> bool {
        let lane = job.queue_lane();
        match self.senders[idx].push_blocking(job) {
            Ok(()) => true,
            Err(FairWorkerPushError) => {
                if lane == EncryptWorkerLane::Bulk {
                    record_encrypt_worker_backpressure_drop(idx);
                }
                debug!(worker = idx, "EncryptWorker thread gone; dropping committed bulk job");
                false
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn dispatch_linux_wg_bulk_batch_unmeasured(
        &self,
        jobs: Vec<FmpSendJob>,
    ) -> Result<(), Vec<FmpSendJob>> {
        let packet_count = jobs.len();
        crate::perf_profile::record_linux_wg_batch_admission(packet_count);
        if self.linux_wg_batch_senders.is_empty() {
            crate::perf_profile::record_linux_wg_batch_admission_unavailable(packet_count);
            return Err(jobs);
        }
        if packet_count < LINUX_WG_BATCH_MIN_PACKETS {
            crate::perf_profile::record_linux_wg_batch_admission_too_small(packet_count);
            return Err(jobs);
        }

        let Some(selected_targets) =
            linux_wg_bulk_batch_selected_targets(&jobs, LINUX_WG_BATCH_MIN_PACKETS)
        else {
            crate::perf_profile::record_linux_wg_batch_admission_no_target(packet_count);
            return Err(jobs);
        };

        let mut dispatched_wg_run = false;
        let mut fallback_jobs = Vec::new();
        let mut run = Vec::new();
        let mut run_target = None;
        for job in jobs {
            let target_key = job.send_target_key();
            if selected_targets.contains_key(&target_key) {
                if run_target.is_some_and(|current| current != target_key) {
                    self.dispatch_pending_linux_wg_bulk_run(&mut run, &mut dispatched_wg_run);
                }
                run_target = Some(target_key);
                run.push(job);
            } else {
                self.dispatch_pending_linux_wg_bulk_run(&mut run, &mut dispatched_wg_run);
                run_target = None;
                fallback_jobs.push(job);
            }
        }
        self.dispatch_pending_linux_wg_bulk_run(&mut run, &mut dispatched_wg_run);

        if dispatched_wg_run {
            if fallback_jobs.is_empty() {
                Ok(())
            } else {
                crate::perf_profile::record_linux_wg_batch_admission_fallback(fallback_jobs.len());
                Err(fallback_jobs)
            }
        } else {
            crate::perf_profile::record_linux_wg_batch_admission_no_target(fallback_jobs.len());
            Err(fallback_jobs)
        }
    }

    #[cfg(target_os = "linux")]
    fn dispatch_linux_wg_bulk_batch_blocking_unmeasured(
        &self,
        jobs: Vec<FmpSendJob>,
    ) -> Result<bool, Vec<FmpSendJob>> {
        let packet_count = jobs.len();
        crate::perf_profile::record_linux_wg_batch_admission(packet_count);
        if self.linux_wg_batch_senders.is_empty() {
            crate::perf_profile::record_linux_wg_batch_admission_unavailable(packet_count);
            return Err(jobs);
        }
        if packet_count < LINUX_WG_BATCH_MIN_PACKETS {
            crate::perf_profile::record_linux_wg_batch_admission_too_small(packet_count);
            return Err(jobs);
        }

        let Some(selected_targets) =
            linux_wg_bulk_batch_selected_targets(&jobs, LINUX_WG_BATCH_MIN_PACKETS)
        else {
            crate::perf_profile::record_linux_wg_batch_admission_no_target(packet_count);
            return Err(jobs);
        };

        let mut dispatched_wg_run = false;
        let mut fallback_jobs = Vec::new();
        let mut run = Vec::new();
        let mut run_target = None;
        let mut all_enqueued = true;

        for job in jobs {
            let target_key = job.send_target_key();
            if selected_targets.contains_key(&target_key) {
                if run_target.is_some_and(|current| current != target_key) {
                    all_enqueued &= self.dispatch_pending_linux_wg_bulk_run_blocking(
                        &mut run,
                        &mut dispatched_wg_run,
                    );
                }
                run_target = Some(target_key);
                run.push(job);
            } else {
                all_enqueued &= self
                    .dispatch_pending_linux_wg_bulk_run_blocking(&mut run, &mut dispatched_wg_run);
                run_target = None;
                fallback_jobs.push(job);
            }
        }
        all_enqueued &=
            self.dispatch_pending_linux_wg_bulk_run_blocking(&mut run, &mut dispatched_wg_run);

        if dispatched_wg_run {
            if fallback_jobs.is_empty() {
                Ok(all_enqueued)
            } else {
                crate::perf_profile::record_linux_wg_batch_admission_fallback(fallback_jobs.len());
                Err(fallback_jobs)
            }
        } else {
            crate::perf_profile::record_linux_wg_batch_admission_no_target(fallback_jobs.len());
            Err(fallback_jobs)
        }
    }

    #[cfg(target_os = "linux")]
    fn dispatch_pending_linux_wg_bulk_run(
        &self,
        run: &mut Vec<FmpSendJob>,
        dispatched_wg_run: &mut bool,
    ) {
        if run.is_empty() {
            return;
        }
        let jobs = std::mem::take(run);
        self.dispatch_linux_wg_bulk_run_unmeasured(jobs);
        *dispatched_wg_run = true;
    }

    #[cfg(target_os = "linux")]
    fn dispatch_pending_linux_wg_bulk_run_blocking(
        &self,
        run: &mut Vec<FmpSendJob>,
        dispatched_wg_run: &mut bool,
    ) -> bool {
        if run.is_empty() {
            return true;
        }
        let jobs = std::mem::take(run);
        *dispatched_wg_run = true;
        self.dispatch_linux_wg_bulk_run_blocking_unmeasured(jobs)
    }

    #[cfg(target_os = "linux")]
    fn dispatch_linux_wg_bulk_run_unmeasured(&self, jobs: Vec<FmpSendJob>) {
        debug_assert!(!jobs.is_empty());
        let first = jobs.first().expect("non-empty WG run");
        debug_assert!(first.bulk_endpoint_data);
        let target_key = first.send_target_key();
        debug_assert!(
            jobs.iter()
                .all(|job| job.bulk_endpoint_data && job.send_target_key() == target_key)
        );

        let flow = self
            .linux_wg_batch_flows
            .flow_for(target_key, first.send_target.clone());
        let chunk_size = DEFAULT_LINUX_WG_BATCH_CHUNK_SIZE;
        let mut chunk = Vec::with_capacity(chunk_size);

        for job in jobs {
            chunk.push(QueuedFmpSendJob::direct(job));
            if chunk.len() >= chunk_size {
                self.dispatch_linux_wg_chunk(Arc::clone(&flow), std::mem::take(&mut chunk));
                chunk = Vec::with_capacity(chunk_size);
            }
        }
        if !chunk.is_empty() {
            self.dispatch_linux_wg_chunk(flow, chunk);
        }
    }

    #[cfg(target_os = "linux")]
    fn dispatch_linux_wg_bulk_run_blocking_unmeasured(&self, jobs: Vec<FmpSendJob>) -> bool {
        debug_assert!(!jobs.is_empty());
        let first = jobs.first().expect("non-empty WG run");
        debug_assert!(first.bulk_endpoint_data);
        let target_key = first.send_target_key();
        debug_assert!(
            jobs.iter()
                .all(|job| job.bulk_endpoint_data && job.send_target_key() == target_key)
        );

        let flow = self
            .linux_wg_batch_flows
            .flow_for(target_key, first.send_target.clone());
        let chunk_size = DEFAULT_LINUX_WG_BATCH_CHUNK_SIZE;
        let mut chunk = Vec::with_capacity(chunk_size);
        let mut all_enqueued = true;

        for job in jobs {
            chunk.push(QueuedFmpSendJob::direct(job));
            if chunk.len() >= chunk_size {
                all_enqueued &= self
                    .dispatch_linux_wg_chunk_blocking(Arc::clone(&flow), std::mem::take(&mut chunk));
                chunk = Vec::with_capacity(chunk_size);
            }
        }
        if !chunk.is_empty() {
            all_enqueued &= self.dispatch_linux_wg_chunk_blocking(flow, chunk);
        }

        all_enqueued
    }

    #[cfg(target_os = "linux")]
    fn dispatch_linux_wg_chunk(
        &self,
        flow: Arc<LinuxWgBatchSendFlow>,
        jobs: Vec<QueuedFmpSendJob>,
    ) {
        if jobs.is_empty() {
            return;
        }
        crate::perf_profile::record_linux_wg_batch_chunk(
            jobs.len(),
            DEFAULT_LINUX_WG_BATCH_CHUNK_SIZE,
        );

        let ready = Arc::new(LinuxWgSendBatch::default());
        if flow.try_enqueue(Arc::clone(&ready)).is_err() {
            crate::perf_profile::record_linux_wg_batch_flow_queue_full(jobs.len());
            self.drop_linux_wg_jobs(0, &jobs);
            return;
        }

        let idx = self
            .next_wg_batch_worker
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.linux_wg_batch_senders.len();
        for job in &jobs {
            crate::perf_profile::record_fmp_worker_dispatch_target(idx, job.endpoint_flow_keyed());
        }

        let batch = LinuxWgEncryptBatch { ready, jobs };
        match self.linux_wg_batch_senders[idx].try_send(batch) {
            Ok(()) => {}
            Err(TrySendError::Full(batch)) | Err(TrySendError::Disconnected(batch)) => {
                crate::perf_profile::record_linux_wg_batch_worker_queue_full(batch.jobs.len());
                self.drop_linux_wg_jobs(idx, &batch.jobs);
                batch.ready.complete(Vec::new());
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn dispatch_linux_wg_chunk_blocking(
        &self,
        flow: Arc<LinuxWgBatchSendFlow>,
        jobs: Vec<QueuedFmpSendJob>,
    ) -> bool {
        if jobs.is_empty() {
            return true;
        }
        crate::perf_profile::record_linux_wg_batch_chunk(
            jobs.len(),
            DEFAULT_LINUX_WG_BATCH_CHUNK_SIZE,
        );

        let ready = Arc::new(LinuxWgSendBatch::default());
        if !flow.enqueue_blocking(Arc::clone(&ready)) {
            crate::perf_profile::record_linux_wg_batch_flow_queue_full(jobs.len());
            self.drop_linux_wg_jobs(0, &jobs);
            return false;
        }

        let idx = self
            .next_wg_batch_worker
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.linux_wg_batch_senders.len();
        for job in &jobs {
            crate::perf_profile::record_fmp_worker_dispatch_target(idx, job.endpoint_flow_keyed());
        }

        let batch = LinuxWgEncryptBatch { ready, jobs };
        match self.linux_wg_batch_senders[idx].send(batch) {
            Ok(()) => true,
            Err(SendError(batch)) => {
                crate::perf_profile::record_linux_wg_batch_worker_queue_full(batch.jobs.len());
                self.drop_linux_wg_jobs(idx, &batch.jobs);
                batch.ready.complete(Vec::new());
                false
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn drop_linux_wg_jobs(&self, idx: usize, jobs: &[QueuedFmpSendJob]) {
        for job in jobs {
            record_encrypt_worker_queue_full(job.queue_lane());
            record_encrypt_worker_backpressure_drop(idx);
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_wg_bulk_batch_selected_targets(
    jobs: &[FmpSendJob],
    min_packets: usize,
) -> Option<HashMap<SendTargetKey, usize>> {
    if jobs.len() < min_packets {
        return None;
    }

    let mut targets = HashMap::new();
    for job in jobs {
        if !job.bulk_endpoint_data {
            return None;
        }
        let count = targets.entry(job.send_target_key()).or_insert(0usize);
        *count = count.saturating_add(1);
    }

    targets.retain(|_, count| *count >= min_packets);
    (!targets.is_empty()).then_some(targets)
}

#[cfg(all(test, not(target_os = "macos")))]
fn encrypt_worker_pool_for_test(senders: Vec<WorkerSender>) -> EncryptWorkerPool {
    EncryptWorkerPool {
        senders: Arc::from(senders.into_boxed_slice()),
        #[cfg(target_os = "linux")]
        linux_wg_batch_senders: Arc::from(Vec::<Sender<LinuxWgEncryptBatch>>::new()),
        #[cfg(target_os = "linux")]
        linux_wg_batch_flows: Arc::new(LinuxWgBatchSendFlows::default()),
        #[cfg(target_os = "linux")]
        next_wg_batch_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    }
}

fn encrypt_worker_dispatch_timer() -> Option<std::time::Instant> {
    if crate::perf_profile::enabled() {
        Some(std::time::Instant::now())
    } else {
        None
    }
}

fn record_encrypt_worker_dispatch(started_at: Option<std::time::Instant>, count: usize) {
    let Some(started_at) = started_at else {
        return;
    };
    crate::perf_profile::record_fmp_worker_dispatch(
        started_at.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        count,
    );
}

fn record_encrypt_worker_queue_full(lane: EncryptWorkerLane) {
    crate::perf_profile::record_encrypt_worker_queue_full(lane == EncryptWorkerLane::Priority);
}

fn record_encrypt_worker_backpressure_drop(worker: usize) {
    crate::perf_profile::record_event(crate::perf_profile::Event::EncryptWorkerBulkDropped);
    static DROP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(100_000) {
        warn!(
            worker,
            drops = n + 1,
            "EncryptWorker channel full; dropping bulk data packet"
        );
    }
}

#[cfg(target_os = "linux")]
struct LinuxWgEncryptBatch {
    ready: Arc<LinuxWgSendBatch>,
    jobs: Vec<QueuedFmpSendJob>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct LinuxWgSendBatch {
    state: Mutex<LinuxWgSendBatchState>,
    ready_cv: Condvar,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct LinuxWgSendBatchState {
    groups: Option<Vec<SelectedSendBatch>>,
}

#[cfg(target_os = "linux")]
impl LinuxWgSendBatch {
    fn complete(&self, groups: Vec<SelectedSendBatch>) {
        let mut state = self.state.lock().expect("Linux WG batch state poisoned");
        debug_assert!(state.groups.is_none());
        state.groups = Some(groups);
        drop(state);
        self.ready_cv.notify_one();
    }

    fn wait(&self) -> Vec<SelectedSendBatch> {
        let mut state = self.state.lock().expect("Linux WG batch state poisoned");
        loop {
            if let Some(groups) = state.groups.take() {
                return groups;
            }
            state = self
                .ready_cv
                .wait(state)
                .expect("Linux WG batch state poisoned");
        }
    }
}

#[cfg(target_os = "linux")]
type LinuxWgBatchSendFlowKey = SendTargetKey;

#[cfg(target_os = "linux")]
const LINUX_WG_BATCH_WORKER_CHANNEL_CAP: usize = 1024;
#[cfg(target_os = "linux")]
const LINUX_WG_BATCH_FLOW_CHANNEL_CAP: usize = 1024;
#[cfg(target_os = "linux")]
const LINUX_WG_BATCH_MIN_PACKETS: usize = 16;
#[cfg(target_os = "linux")]
const LINUX_WG_BATCH_FLOW_IDLE_MS: u64 = 120_000;

#[cfg(target_os = "linux")]
#[derive(Default)]
struct LinuxWgBatchSendFlows {
    flows: Mutex<HashMap<LinuxWgBatchSendFlowKey, Arc<LinuxWgBatchSendFlow>>>,
    last_prune_ms: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "linux")]
impl LinuxWgBatchSendFlows {
    fn flow_for(
        &self,
        key: LinuxWgBatchSendFlowKey,
        send_target: SelectedSendTarget,
    ) -> Arc<LinuxWgBatchSendFlow> {
        let now_ms = linux_wg_batch_now_ms();
        let mut flows = self.flows.lock().expect("Linux WG flow map poisoned");
        self.prune_idle_locked(&mut flows, now_ms);
        if let Some(flow) = flows.get(&key) {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = LinuxWgBatchSendFlow::spawn(
            key,
            send_target,
            now_ms,
            LINUX_WG_BATCH_FLOW_CHANNEL_CAP,
        );
        flows.insert(key, Arc::clone(&flow));
        flow
    }

    fn prune_idle_locked(
        &self,
        flows: &mut HashMap<LinuxWgBatchSendFlowKey, Arc<LinuxWgBatchSendFlow>>,
        now_ms: u64,
    ) {
        let last = self
            .last_prune_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last) < 10_000 {
            return;
        }
        if self
            .last_prune_ms
            .compare_exchange(
                last,
                now_ms,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        flows.retain(|_, flow| !flow.is_idle(now_ms, LINUX_WG_BATCH_FLOW_IDLE_MS));
    }
}

#[cfg(target_os = "linux")]
struct LinuxWgBatchSendFlow {
    sender: Sender<Arc<LinuxWgSendBatch>>,
    inflight: Arc<std::sync::atomic::AtomicUsize>,
    last_used_ms: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "linux")]
impl LinuxWgBatchSendFlow {
    fn spawn(
        key: LinuxWgBatchSendFlowKey,
        send_target: SelectedSendTarget,
        now_ms: u64,
        cap: usize,
    ) -> Arc<Self> {
        let (sender, receiver) = bounded(cap);
        let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let thread_inflight = Arc::clone(&inflight);
        std::thread::Builder::new()
            .name(format!("fips-linux-wg-send-{}", key.socket_fd))
            .spawn(move || run_linux_wg_batch_sender(key, send_target, receiver, thread_inflight))
            .expect("failed to spawn fips Linux WG-batch sender thread");
        Arc::new(Self {
            sender,
            inflight,
            last_used_ms: std::sync::atomic::AtomicU64::new(now_ms),
        })
    }

    fn try_enqueue(
        &self,
        batch: Arc<LinuxWgSendBatch>,
    ) -> Result<(), TrySendError<Arc<LinuxWgSendBatch>>> {
        match self.sender.try_send(batch) {
            Ok(()) => {
                self.inflight
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn enqueue_blocking(&self, batch: Arc<LinuxWgSendBatch>) -> bool {
        match self.sender.send(batch) {
            Ok(()) => {
                self.inflight
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                true
            }
            Err(_) => false,
        }
    }

    fn mark_used(&self, now_ms: u64) {
        self.last_used_ms
            .store(now_ms, std::sync::atomic::Ordering::Relaxed);
    }

    fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
        let last_used = self.last_used_ms.load(std::sync::atomic::Ordering::Relaxed);
        now_ms.saturating_sub(last_used) >= idle_ms
            && self.inflight.load(std::sync::atomic::Ordering::Relaxed) == 0
    }
}

#[cfg(target_os = "linux")]
fn run_linux_wg_batch_sender(
    key: LinuxWgBatchSendFlowKey,
    send_target: SelectedSendTarget,
    receiver: Receiver<Arc<LinuxWgSendBatch>>,
    inflight: Arc<std::sync::atomic::AtomicUsize>,
) {
    trace!(
        socket_fd = key.socket_fd,
        connected_fd = ?key.connected_fd,
        dest = %send_target.dest_addr(),
        "Linux WG-batch UDP sender starting"
    );

    loop {
        let Ok(batch) = receiver.recv() else {
            break;
        };
        let wait_started_at = crate::perf_profile::enabled().then(std::time::Instant::now);
        let groups = batch.wait();
        if let Some(wait_started_at) = wait_started_at {
            crate::perf_profile::record_linux_wg_batch_sender_wait(
                wait_started_at.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            );
        }

        if !groups.is_empty() {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
            if let Err(err) = flush_linux_send_groups_sync(groups) {
                debug!(
                    socket_fd = key.socket_fd,
                    connected_fd = ?key.connected_fd,
                    dest = %send_target.dest_addr(),
                    error = %err,
                    "Linux WG-batch UDP send failed"
                );
            }
        }
        inflight.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
fn linux_wg_batch_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MacSendFlowKey {
    target: SendTargetKey,
}

#[cfg(target_os = "macos")]
impl MacSendFlowKey {
    fn from_job(job: &FmpSendJob) -> Self {
        Self {
            target: job.send_target_key(),
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacSequencedSendFlows {
    flows: Mutex<HashMap<MacSendFlowKey, Arc<MacSequencedSendFlow>>>,
    last_prune_ms: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "macos")]
impl MacSequencedSendFlows {
    fn flow_for(&self, job: &FmpSendJob) -> Arc<MacSequencedSendFlow> {
        let now_ms = mac_now_ms();
        let key = MacSendFlowKey::from_job(job);

        let mut flows = self.flows.lock().expect("mac send flow map poisoned");
        self.prune_idle_locked(&mut flows, now_ms);
        if let Some(flow) = flows.get(&key) {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = MacSequencedSendFlow::spawn(key, job.send_target.clone(), now_ms);
        flows.insert(key, Arc::clone(&flow));
        flow
    }

    fn prune_idle_locked(
        &self,
        flows: &mut HashMap<MacSendFlowKey, Arc<MacSequencedSendFlow>>,
        now_ms: u64,
    ) {
        let last = self
            .last_prune_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last) < 10_000 {
            return;
        }
        if self
            .last_prune_ms
            .compare_exchange(
                last,
                now_ms,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        let idle_ms = mac_send_flow_idle_ms();
        flows.retain(|_, flow| {
            if flow.is_idle(now_ms, idle_ms) {
                flow.close();
                false
            } else {
                true
            }
        });
    }
}

#[cfg(target_os = "macos")]
fn macos_ordered_sender_enabled() -> bool {
    // Ordered mode gives Darwin the same broad shape as Linux's WG-batch
    // sender: FMP/FSP AEAD can run across the worker pool, while one flow
    // thread preserves UDP order for the kernel send target. Keep the env as
    // an opt-out for NIC/Wi-Fi A/Bs.
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| {
        parse_macos_ordered_sender_enabled(
            std::env::var("FIPS_MACOS_ORDERED_SENDER")
                .ok()
                .as_deref(),
        )
    })
}

#[cfg(target_os = "macos")]
fn parse_macos_ordered_sender_enabled(raw: Option<&str>) -> bool {
    raw.map(|raw| {
        !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        )
    })
    .unwrap_or(true)
}

#[cfg(target_os = "macos")]
fn macos_worker_stride() -> usize {
    // One-packet round-robin maximizes FMP AEAD parallelism but wakes an idle
    // worker for nearly every packet on Darwin. Short strides let a hot worker
    // drain a local queue batch before the next worker is signalled, while still
    // spreading sustained single-peer traffic across the full pool.
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_WORKER_STRIDE")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 64)
    })
}

#[cfg(target_os = "macos")]
fn macos_worker_batch_size() -> usize {
    // The direct Darwin sender has no sendmmsg/GSO equivalent, so a large
    // worker-drain batch becomes a tight burst of send/sendto calls. MacBook
    // Wi-Fi -> Ethernet tests showed the previous default of 32 could trigger
    // TCP collapse and long queue waits even when Darwin did not report
    // ENOBUFS. A smaller default keeps the kernel/radio pacer in the loop
    // without waking the worker for every datagram; keep this runtime-tunable
    // for LAN/NIC-specific A/B tests.
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_WORKER_BATCH")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(8)
            .clamp(1, 64)
    })
}

#[cfg(target_os = "macos")]
fn mac_send_flow_idle_ms() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_SEND_FLOW_IDLE_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(120_000)
            .max(10_000)
    })
}

#[cfg(target_os = "macos")]
fn mac_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn send_one_with_backpressure(
    fd: RawFd,
    connected: bool,
    dest_addr: &SocketAddr,
    packet: &[u8],
    backpressure: &mut SendBackpressurePacer,
    drop_on_backpressure: bool,
) -> std::io::Result<()> {
    loop {
        let result = if connected {
            send_connected_raw(fd, packet)
        } else {
            send_one_raw(fd, packet, dest_addr)
        };
        match result {
            Ok(_) => {
                backpressure.record_success();
                record_udp_send_path(connected, 1);
                return Ok(());
            }
            Err(err) if is_send_backpressure(&err) => {
                let pacer_requested_drop = backpressure.pause(&err);
                if matches!(
                    send_backpressure_decision(pacer_requested_drop, drop_on_backpressure),
                    SendBackpressureDecision::DropCurrentBulk
                ) {
                    record_udp_send_backpressure_drop(&err);
                    return Ok(());
                }
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(target_os = "macos")]
struct MacSequencedSendFlow {
    key: MacSendFlowKey,
    send_target: SelectedSendTarget,
    next_seq: std::sync::atomic::AtomicU64,
    last_used_ms: std::sync::atomic::AtomicU64,
    state: Mutex<MacSendFlowState>,
    ready_cv: Condvar,
    space_cv: Condvar,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacSendFlowState {
    next_send_seq: u64,
    pending: BTreeMap<u64, MacSendItem>,
    closed: bool,
}

#[cfg(target_os = "macos")]
struct MacCompletionGroup {
    flow_key: MacSendFlowKey,
    flow: Arc<MacSequencedSendFlow>,
    items: Vec<(u64, MacSendItem)>,
}

#[cfg(target_os = "macos")]
enum MacSendItem {
    Packet {
        packet: Vec<u8>,
        drop_on_backpressure: bool,
    },
    Skip,
}

#[cfg(target_os = "macos")]
impl MacCompletionGroup {
    fn new(flow: Arc<MacSequencedSendFlow>, seq: u64, item: MacSendItem) -> Self {
        let flow_key = flow.key;
        Self {
            flow_key,
            flow,
            items: vec![(seq, item)],
        }
    }

    #[cfg(test)]
    fn target_key(&self) -> MacSendFlowKey {
        self.flow_key
    }

    fn push(&mut self, flow: &Arc<MacSequencedSendFlow>, seq: u64, item: MacSendItem) {
        debug_assert_eq!(
            self.flow_key, flow.key,
            "macOS completion group must keep the queued flow key"
        );
        debug_assert!(
            Arc::ptr_eq(&self.flow, flow),
            "macOS completion group must not merge a different flow owner"
        );
        self.items.push((seq, item));
    }

    fn complete(self) {
        self.flow.complete_many(self.items);
    }
}

#[cfg(target_os = "macos")]
impl MacSequencedSendFlow {
    fn spawn(key: MacSendFlowKey, send_target: SelectedSendTarget, now_ms: u64) -> Arc<Self> {
        let flow = Arc::new(Self {
            key,
            send_target,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            last_used_ms: std::sync::atomic::AtomicU64::new(now_ms),
            state: Mutex::new(MacSendFlowState::default()),
            ready_cv: Condvar::new(),
            space_cv: Condvar::new(),
        });
        let thread_flow = Arc::clone(&flow);
        std::thread::Builder::new()
            .name(format!("fips-mac-send-{}", key.target.socket_fd))
            .spawn(move || thread_flow.run())
            .expect("failed to spawn fips macOS send thread");
        flow
    }

    fn reserve_seq(&self) -> u64 {
        self.next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn mark_used(&self, now_ms: u64) {
        self.last_used_ms
            .store(now_ms, std::sync::atomic::Ordering::Relaxed);
    }

    fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
        let last_used = self.last_used_ms.load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last_used) < idle_ms {
            return false;
        }

        let state = self.state.lock().expect("mac send flow state poisoned");
        state.pending.is_empty()
            && state.next_send_seq == self.next_seq.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("mac send flow state poisoned");
        state.closed = true;
        drop(state);
        self.ready_cv.notify_one();
        self.space_cv.notify_all();
    }

    fn complete_many(&self, items: Vec<(u64, MacSendItem)>) {
        const PENDING_CAP: usize = 4096;
        if items.is_empty() {
            return;
        }

        let mut state = self.state.lock().expect("mac send flow state poisoned");
        if state.closed {
            return;
        }
        let mut wakes_sender = false;
        for (seq, item) in items {
            while state.pending.len() >= PENDING_CAP && seq != state.next_send_seq && !wakes_sender
            {
                state = self
                    .space_cv
                    .wait(state)
                    .expect("mac send flow state poisoned");
            }
            if seq == state.next_send_seq {
                wakes_sender = true;
            }
            state.pending.insert(seq, item);
        }
        drop(state);
        if wakes_sender {
            self.ready_cv.notify_one();
        }
    }

    #[cfg(test)]
    fn take_next_ready_for_test(&self) -> Option<MacSendItem> {
        let mut state = self.state.lock().expect("mac send flow state poisoned");
        let next = state.next_send_seq;
        if let Some(item) = state.pending.remove(&next) {
            state.next_send_seq = next.wrapping_add(1);
            self.space_cv.notify_one();
            return Some(item);
        }

        None
    }

    fn run(self: Arc<Self>) {
        trace!(
            socket_fd = self.key.target.socket_fd,
            connected_fd = ?self.key.target.connected_fd,
            dest = %self.send_target.dest_addr(),
            "macOS ordered UDP sender starting"
        );
        let (fd, connected) = self.send_target.fd_and_connected();
        let mut backpressure = SendBackpressurePacer::default();
        let mut rate_pacer = MacSendRatePacer::default();

        loop {
            let item = {
                let mut state = self.state.lock().expect("mac send flow state poisoned");
                loop {
                    let next = state.next_send_seq;
                    if let Some(item) = state.pending.remove(&next) {
                        state.next_send_seq = next.wrapping_add(1);
                        self.space_cv.notify_one();
                        break item;
                    }
                    if state.closed {
                        return;
                    }
                    state = self
                        .ready_cv
                        .wait(state)
                        .expect("mac send flow state poisoned");
                }
            };

            match item {
                MacSendItem::Packet {
                    packet,
                    drop_on_backpressure,
                    ..
                } => {
                    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
                    rate_pacer.pace(packet.len());
                    if let Err(err) = send_one_with_backpressure(
                        fd,
                        connected,
                        &self.send_target.dest_addr(),
                        &packet,
                        &mut backpressure,
                        drop_on_backpressure,
                    ) {
                        debug!(
                            socket_fd = self.key.target.socket_fd,
                            connected_fd = ?self.key.target.connected_fd,
                            dest = %self.send_target.dest_addr(),
                            error = %err,
                            "macOS ordered UDP send failed"
                        );
                    }
                }
                MacSendItem::Skip => {}
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn push_mac_completion(
    groups: &mut Vec<MacCompletionGroup>,
    flow: Arc<MacSequencedSendFlow>,
    seq: u64,
    item: MacSendItem,
) {
    if let Some(group) = groups
        .iter_mut()
        .find(|group| Arc::ptr_eq(&group.flow, &flow))
    {
        group.push(&flow, seq, item);
    } else {
        groups.push(MacCompletionGroup::new(flow, seq, item));
    }
}
