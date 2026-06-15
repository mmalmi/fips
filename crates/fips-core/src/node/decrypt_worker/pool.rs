/// Handle to the decrypt worker pool. Shard-style: each worker is one
/// OS thread that owns its sessions outright. Dispatch is
/// deterministic on `session_key` so a session always reaches the same
/// shard.
#[derive(Clone)]
pub(crate) struct DecryptWorkerPool {
    senders: Arc<[DecryptWorkerSender]>,
    direct_delivery_sink: DecryptDirectSessionDeliverySink,
    fmp_aead_helpers: Option<Arc<FmpAeadHelperPool>>,
    fmp_preowner_aead_helpers: bool,
    fmp_preowner_fsp_fusion: bool,
    fmp_aead_sessions: Arc<RwLock<HashMap<DecryptSessionKey, Arc<FmpSharedCryptoSession>>>>,
    fsp_aead_helpers: Option<Arc<FspAeadHelperPool>>,
    fsp_aead_sessions: Arc<RwLock<HashMap<NodeAddr, Arc<FspSharedCryptoSession>>>>,
}

#[derive(Clone)]
struct DecryptWorkerSender {
    priority: Sender<WorkerMsg>,
    bulk: Sender<DecryptWorkerBulkItem>,
    fmp_aead_completion: Sender<FmpAeadCompletion>,
    fsp_aead_completion: Sender<FspAeadCompletion>,
    bulk_queued_packets: Arc<AtomicUsize>,
    bulk_packet_cap: usize,
}

struct FmpAeadHelperPool {
    tx: Sender<FmpAeadHelperJob>,
}

struct FspAeadHelperPool {
    tx: Sender<FspAeadHelperJob>,
}

impl FmpAeadHelperPool {
    fn spawn(n: usize, channel_cap: usize) -> Option<Arc<Self>> {
        if n == 0 {
            return None;
        }
        let (tx, rx) = bounded::<FmpAeadHelperJob>(channel_cap.max(1));
        for i in 0..n {
            let helper_rx = rx.clone();
            std::thread::Builder::new()
                .name(format!("fips-decrypt-fmp-aead-{i}"))
                .spawn(move || run_fmp_aead_helper(i, helper_rx))
                .expect("failed to spawn fips-decrypt-fmp-aead OS thread");
        }
        Some(Arc::new(Self { tx }))
    }

    #[allow(clippy::result_large_err)]
    fn try_dispatch(&self, job: FmpAeadHelperJob) -> Result<(), FmpAeadHelperJob> {
        match self.tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job)) | Err(TrySendError::Disconnected(job)) => Err(job),
        }
    }

    fn has_room(&self) -> bool {
        !self.tx.is_full()
    }
}

impl FspAeadHelperPool {
    fn spawn(n: usize, channel_cap: usize) -> Option<Arc<Self>> {
        if n == 0 {
            return None;
        }
        let (tx, rx) = bounded::<FspAeadHelperJob>(channel_cap.max(1));
        for i in 0..n {
            let helper_rx = rx.clone();
            std::thread::Builder::new()
                .name(format!("fips-decrypt-fsp-aead-{i}"))
                .spawn(move || run_fsp_aead_helper(i, helper_rx))
                .expect("failed to spawn fips-decrypt-fsp-aead OS thread");
        }
        Some(Arc::new(Self { tx }))
    }

    #[allow(clippy::result_large_err)]
    fn try_dispatch(&self, job: FspAeadHelperJob) -> Result<(), FspAeadHelperJob> {
        match self.tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job)) | Err(TrySendError::Disconnected(job)) => Err(job),
        }
    }
}

fn run_fmp_aead_helper(idx: usize, rx: Receiver<FmpAeadHelperJob>) {
    trace!(helper = idx, "FMP AEAD helper thread starting");
    while let Ok(mut job) = rx.recv() {
        crate::perf_profile::record_since_count(
            crate::perf_profile::Stage::FmpAeadHelperQueueWait,
            job.helper_queued_at,
            1,
        );
        let Some(completion_tx) = job.completion_tx.take() else {
            continue;
        };
        let completion = job.into_completion();
        if completion_tx.send(completion).is_err() {
            debug!(
                helper = idx,
                "FMP AEAD helper completion owner gone; dropping completion"
            );
        }
    }
    trace!(helper = idx, "FMP AEAD helper thread exiting");
}

fn run_fsp_aead_helper(idx: usize, rx: Receiver<FspAeadHelperJob>) {
    trace!(helper = idx, "FSP AEAD helper thread starting");
    while let Ok(mut job) = rx.recv() {
        let Some(completion_tx) = job.completion_tx.take() else {
            continue;
        };
        let completion = job.into_completion();
        if completion_tx.send(completion).is_err() {
            debug!(
                helper = idx,
                "FSP AEAD helper completion owner gone; dropping completion"
            );
        }
    }
    trace!(helper = idx, "FSP AEAD helper thread exiting");
}

impl DecryptWorkerPool {
    #[cfg(test)]
    pub(crate) fn spawn(n: usize) -> Self {
        Self::spawn_with_direct_delivery_sink(n, DecryptDirectSessionDeliverySink::default())
    }

    pub(crate) fn spawn_with_direct_delivery_sink(
        n: usize,
        direct_delivery_sink: DecryptDirectSessionDeliverySink,
    ) -> Self {
        let n = n.max(1);
        let bulk_channel_cap = bulk_channel_cap();
        let priority_channel_cap = priority_channel_cap();
        let mut senders = Vec::with_capacity(n);
        let mut receivers = Vec::with_capacity(n);
        for _ in 0..n {
            let (priority_tx, priority_rx) = bounded::<WorkerMsg>(priority_channel_cap);
            let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(bulk_channel_cap);
            let (fmp_aead_completion_tx, fmp_aead_completion_rx) =
                bounded::<FmpAeadCompletion>(bulk_channel_cap);
            let (fsp_aead_completion_tx, fsp_aead_completion_rx) =
                bounded::<FspAeadCompletion>(bulk_channel_cap);
            let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
            receivers.push((
                priority_rx,
                fmp_aead_completion_rx,
                fsp_aead_completion_rx,
                bulk_rx,
                Arc::clone(&bulk_queued_packets),
            ));
            senders.push(DecryptWorkerSender {
                priority: priority_tx,
                bulk: bulk_tx,
                fmp_aead_completion: fmp_aead_completion_tx,
                fsp_aead_completion: fsp_aead_completion_tx,
                bulk_queued_packets,
                bulk_packet_cap: bulk_channel_cap,
            });
        }
        let fmp_aead_helpers = FmpAeadHelperPool::spawn(fmp_aead_helper_count(), bulk_channel_cap);
        let fmp_preowner_aead_helpers =
            fmp_preowner_aead_helper_enabled() && fmp_aead_helpers.is_some();
        let fmp_preowner_fsp_fusion =
            fmp_preowner_aead_helpers && fmp_preowner_fsp_fusion_enabled();
        let fsp_aead_helpers =
            FspAeadHelperPool::spawn(fsp_ordered_aead_helper_count(), bulk_channel_cap);
        let pool = Self {
            senders: senders.into(),
            direct_delivery_sink,
            fmp_aead_helpers,
            fmp_preowner_aead_helpers,
            fmp_preowner_fsp_fusion,
            fmp_aead_sessions: Arc::new(RwLock::new(HashMap::new())),
            fsp_aead_helpers,
            fsp_aead_sessions: Arc::new(RwLock::new(HashMap::new())),
        };
        for (
            i,
            (
                priority_rx,
                fmp_aead_completion_rx,
                fsp_aead_completion_rx,
                bulk_rx,
                worker_bulk_queued_packets,
            ),
        ) in receivers.into_iter().enumerate()
        {
            let worker_pool = pool.clone();
            std::thread::Builder::new()
                .name(format!("fips-decrypt-{i}"))
                .spawn(move || {
                    run_worker(
                        i,
                        worker_pool,
                        priority_rx,
                        fmp_aead_completion_rx,
                        fsp_aead_completion_rx,
                        bulk_rx,
                        worker_bulk_queued_packets,
                    )
                })
                .expect("failed to spawn fips-decrypt OS thread");
        }
        pool
    }

    /// Stable hash from session key → worker index. Same hash is used
    /// for session registration and per-packet dispatch so packets and
    /// registration arrive at the same shard.
    fn worker_idx_for(&self, session_key: DecryptSessionKey) -> usize {
        (decrypt_session_fast_hash(session_key) as usize) % self.senders.len()
    }

    fn worker_idx_for_fsp(&self, source_addr: &NodeAddr) -> usize {
        (decrypt_fsp_session_fast_hash(source_addr) as usize) % self.senders.len()
    }

    fn bulk_batch_packet_max_for(&self, idx: usize) -> usize {
        self.senders[idx]
            .bulk_packet_cap
            .clamp(1, DECRYPT_WORKER_BULK_BATCH_MAX)
    }

    /// Dispatch a per-packet decrypt job. Drops if the per-worker
    /// channel is full (sustained rate overrun); the rx_loop's drain
    /// caps inbound at the same scale upstream so the cliff is
    /// bounded.
    pub fn dispatch_job(&self, mut job: DecryptJob) {
        if self.senders.is_empty() {
            return;
        }
        match self.try_dispatch_fmp_preowner_aead_helper(job) {
            Ok(()) => return,
            Err(returned) => job = returned,
        }
        job.set_trace_enqueued_at(crate::perf_profile::stamp());
        let idx = self.worker_idx_for(job.session_key);
        match decrypt_job_lane(&job) {
            DecryptWorkerLane::Priority => self.dispatch_priority_job(idx, job),
            DecryptWorkerLane::Bulk => self.dispatch_bulk_job(idx, job),
        }
    }

    fn dispatch_priority_job(&self, idx: usize, job: DecryptJob) {
        match self.senders[idx].priority.try_send(WorkerMsg::Job(job)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_priority_drop(idx, "packet");
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; dropping priority job"
                );
            }
        }
    }

    fn dispatch_bulk_job(&self, idx: usize, job: DecryptJob) {
        self.dispatch_bulk_item(idx, DecryptWorkerBulkItem::Job(job));
    }

    fn fmp_aead_helpers_enabled(&self) -> bool {
        self.fmp_aead_helpers.is_some()
    }

    fn fmp_preowner_aead_helpers_enabled(&self) -> bool {
        self.fmp_preowner_aead_helpers
    }

    fn fmp_preowner_fsp_fusion_enabled(&self) -> bool {
        self.fmp_preowner_fsp_fusion
    }

    fn fmp_aead_session(
        &self,
        session_key: &DecryptSessionKey,
    ) -> Option<Arc<FmpSharedCryptoSession>> {
        self.fmp_aead_sessions
            .read()
            .ok()
            .and_then(|sessions| sessions.get(session_key).cloned())
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_fmp_aead_helper_job(
        &self,
        owner_idx: usize,
        mut job: FmpAeadHelperJob,
    ) -> Result<(), FmpAeadHelperJob> {
        let Some(helpers) = self.fmp_aead_helpers.as_ref() else {
            return Err(job);
        };
        let Some(sender) = self.senders.get(owner_idx) else {
            return Err(job);
        };
        job.completion_tx = Some(sender.fmp_aead_completion.clone());
        job.helper_queued_at = crate::perf_profile::stamp();
        helpers.try_dispatch(job)
    }

    fn send_fmp_aead_completion_blocking(
        &self,
        owner_idx: usize,
        completion: FmpAeadCompletion,
    ) -> bool {
        self.senders
            .get(owner_idx)
            .is_some_and(|sender| sender.fmp_aead_completion.send(completion).is_ok())
    }

    #[allow(clippy::result_large_err)]
    fn try_dispatch_fmp_preowner_aead_helper(
        &self,
        job: DecryptJob,
    ) -> Result<(), DecryptJob> {
        if !self.fmp_preowner_aead_helpers_enabled() || !job.is_bulk_lane() {
            return Err(job);
        }
        let Some(helpers) = self.fmp_aead_helpers.as_ref() else {
            return Err(job);
        };
        if !helpers.has_room() {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DecryptFmpPreownerHelperFallback,
            );
            return Err(job);
        }
        let Some(shared) = self.fmp_aead_session(&job.session_key) else {
            return Err(job);
        };
        if !shared.can_issue_preowner_bulk_ticket() {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DecryptFmpPreownerWindowFallback,
            );
            return Err(job);
        }
        let Some(ticket) = shared.try_issue_preowner_bulk_ticket() else {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DecryptFmpPreownerWindowFallback,
            );
            return Err(job);
        };
        let Some(sender) = self.senders.get(shared.owner_idx) else {
            return Err(job);
        };
        let helper_job = FmpAeadHelperJob::from_preowner_decrypt_job(
            job,
            &shared,
            ticket,
            sender.fmp_aead_completion.clone(),
            self.fmp_preowner_fsp_fusion_enabled()
                .then(|| Arc::clone(&self.fsp_aead_sessions)),
        );
        match helpers.try_dispatch(helper_job) {
            Ok(()) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFmpPreownerHelper,
                );
                Ok(())
            }
            Err(helper_job) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFmpPreownerInlineFallback,
                );
                let owner_idx = shared.owner_idx;
                let completion = helper_job.into_completion();
                let _ = self.send_fmp_aead_completion_blocking(owner_idx, completion);
                Ok(())
            }
        }
    }

    fn fsp_aead_helpers_enabled(&self) -> bool {
        self.fsp_aead_helpers.is_some()
    }

    fn fsp_aead_session(&self, source_addr: &NodeAddr) -> Option<Arc<FspSharedCryptoSession>> {
        self.fsp_aead_sessions
            .read()
            .ok()
            .and_then(|sessions| sessions.get(source_addr).cloned())
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_fsp_aead_helper_job(
        &self,
        owner_idx: usize,
        mut job: FspAeadHelperJob,
    ) -> Result<(), FspAeadHelperJob> {
        let Some(helpers) = self.fsp_aead_helpers.as_ref() else {
            return Err(job);
        };
        let Some(sender) = self.senders.get(owner_idx) else {
            return Err(job);
        };
        job.completion_tx = Some(sender.fsp_aead_completion.clone());
        job.helper_queued_at = crate::perf_profile::stamp();
        helpers.try_dispatch(job)
    }

    fn send_fsp_aead_completion_blocking(
        &self,
        owner_idx: usize,
        completion: FspAeadCompletion,
    ) -> bool {
        self.senders
            .get(owner_idx)
            .is_some_and(|sender| sender.fsp_aead_completion.send(completion).is_ok())
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_fsp_job_or_return(&self, job: FspDecryptJob) -> Result<(), FspDecryptJob> {
        if self.senders.is_empty() {
            return Err(job);
        }
        let idx = self.worker_idx_for_fsp(&job.source_addr);
        match job.lane() {
            DecryptWorkerLane::Priority => self.dispatch_priority_fsp_job_or_return(idx, job),
            DecryptWorkerLane::Bulk => self.dispatch_bulk_fsp_job_or_return(idx, job),
        }
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_priority_fsp_job_or_return(
        &self,
        idx: usize,
        mut job: FspDecryptJob,
    ) -> Result<(), FspDecryptJob> {
        job.set_trace_enqueued_at(crate::perf_profile::stamp());
        match self.senders[idx].priority.try_send(WorkerMsg::FspJob(job)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerQueueFull,
                );
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFspPriorityQueueFullFallback,
                );
                Err(match job {
                    WorkerMsg::FspJob(job) => job,
                    _ => unreachable!("priority FSP dispatch only sends FSP jobs"),
                })
            }
            Err(TrySendError::Disconnected(job)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; falling FSP priority job back to rx_loop"
                );
                Err(match job {
                    WorkerMsg::FspJob(job) => job,
                    _ => unreachable!("priority FSP dispatch only sends FSP jobs"),
                })
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_bulk_fsp_job_or_return(
        &self,
        idx: usize,
        job: FspDecryptJob,
    ) -> Result<(), FspDecryptJob> {
        self.dispatch_bulk_fsp_job_with_stamp_or_return(idx, job, crate::perf_profile::stamp())
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_bulk_fsp_job_with_stamp_or_return(
        &self,
        idx: usize,
        mut job: FspDecryptJob,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Result<(), FspDecryptJob> {
        job.set_trace_enqueued_at(queued_at);
        let sender = &self.senders[idx];
        if !try_reserve_bulk_packets(&sender.bulk_queued_packets, sender.bulk_packet_cap, 1) {
            crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerQueueFull);
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DecryptFspBulkQueueFullFallback,
            );
            return Err(job);
        }

        match sender.bulk.try_send(DecryptWorkerBulkItem::FspJob(job)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(DecryptWorkerBulkItem::FspJob(job))) => {
                release_bulk_packets(&sender.bulk_queued_packets, 1);
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerQueueFull,
                );
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFspBulkQueueFullFallback,
                );
                Err(job)
            }
            Err(TrySendError::Disconnected(DecryptWorkerBulkItem::FspJob(job))) => {
                release_bulk_packets(&sender.bulk_queued_packets, 1);
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; falling FSP bulk job back to rx_loop"
                );
                Err(job)
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                unreachable!("bulk FSP dispatch only sends FSP jobs")
            }
        }
    }

    fn dispatch_bulk_fsp_jobs_individually_or_return(
        &self,
        idx: usize,
        jobs: Vec<FspDecryptJob>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Result<(), Vec<FspDecryptJob>> {
        let mut returned = Vec::new();
        for job in jobs {
            if let Err(job) = self.dispatch_bulk_fsp_job_with_stamp_or_return(idx, job, queued_at) {
                returned.push(job);
            }
        }
        if returned.is_empty() {
            Ok(())
        } else {
            Err(returned)
        }
    }

    fn dispatch_bulk_fsp_job_batch_or_return(
        &self,
        idx: usize,
        mut jobs: Vec<FspDecryptJob>,
    ) -> Result<(), Vec<FspDecryptJob>> {
        debug_assert!(!jobs.is_empty());
        debug_assert!(jobs.len() <= DECRYPT_WORKER_BULK_BATCH_MAX);
        debug_assert!(
            jobs.iter()
                .all(|job| matches!(job.lane(), DecryptWorkerLane::Bulk))
        );

        let queued_at = crate::perf_profile::stamp();
        for job in &mut jobs {
            job.set_trace_enqueued_at(queued_at);
        }

        if jobs.len() == 1 {
            let job = jobs.pop().expect("checked non-empty FSP batch");
            return self
                .dispatch_bulk_fsp_job_with_stamp_or_return(idx, job, queued_at)
                .map_err(|job| vec![job]);
        }

        let packet_count = jobs.len();
        let sender = &self.senders[idx];
        if !try_reserve_bulk_packets(
            &sender.bulk_queued_packets,
            sender.bulk_packet_cap,
            packet_count,
        ) {
            return self.dispatch_bulk_fsp_jobs_individually_or_return(idx, jobs, queued_at);
        }

        match sender.bulk.try_send(DecryptWorkerBulkItem::FspBatch(jobs)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(DecryptWorkerBulkItem::FspBatch(jobs))) => {
                release_bulk_packets(&sender.bulk_queued_packets, packet_count);
                self.dispatch_bulk_fsp_jobs_individually_or_return(idx, jobs, queued_at)
            }
            Err(TrySendError::Disconnected(DecryptWorkerBulkItem::FspBatch(jobs))) => {
                release_bulk_packets(&sender.bulk_queued_packets, packet_count);
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; falling FSP bulk job batch back to rx_loop"
                );
                Err(jobs)
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                unreachable!("bulk FSP batch dispatch only sends FSP batches")
            }
        }
    }

    fn dispatch_bulk_job_batch(&self, idx: usize, mut jobs: Vec<DecryptJob>) {
        debug_assert!(!jobs.is_empty());
        debug_assert!(jobs.len() <= DECRYPT_WORKER_BULK_BATCH_MAX);
        debug_assert!(jobs.iter().all(DecryptJob::is_bulk_lane));

        if self.fmp_preowner_aead_helpers_enabled() {
            let mut owner_jobs = Vec::new();
            let mut keep_owner_order = false;
            for job in jobs {
                if keep_owner_order {
                    owner_jobs.push(job);
                    continue;
                }
                match self.try_dispatch_fmp_preowner_aead_helper(job) {
                    Ok(()) => {}
                    Err(job) => {
                        keep_owner_order = true;
                        owner_jobs.push(job);
                    }
                }
            }
            if owner_jobs.is_empty() {
                return;
            }
            jobs = owner_jobs;
        }

        let queued_at = crate::perf_profile::stamp();
        for job in &mut jobs {
            job.set_trace_enqueued_at(queued_at);
        }

        if jobs.len() == 1 {
            let job = jobs.pop().expect("checked non-empty batch");
            self.dispatch_bulk_job(idx, job);
            return;
        }

        self.dispatch_bulk_item(idx, DecryptWorkerBulkItem::Batch(jobs));
    }

    fn dispatch_bulk_item(&self, idx: usize, item: DecryptWorkerBulkItem) {
        let _ = self.dispatch_bulk_item_or_return(idx, item);
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_bulk_item_or_return(
        &self,
        idx: usize,
        item: DecryptWorkerBulkItem,
    ) -> Result<(), DecryptWorkerBulkItem> {
        let packet_count = item.packet_count();
        let sender = &self.senders[idx];
        if !try_reserve_bulk_packets(
            &sender.bulk_queued_packets,
            sender.bulk_packet_cap,
            packet_count,
        ) {
            record_decrypt_worker_bulk_drop_count(idx, packet_count);
            return Err(item);
        }

        match sender.bulk.try_send(item) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(item)) => {
                release_bulk_packets(&sender.bulk_queued_packets, packet_count);
                record_decrypt_worker_bulk_drop_count(idx, packet_count);
                Err(item)
            }
            Err(TrySendError::Disconnected(item)) => {
                release_bulk_packets(&sender.bulk_queued_packets, packet_count);
                debug!(worker = idx, "DecryptWorker thread gone; dropping bulk job");
                Err(item)
            }
        }
    }

    /// Hand ownership of a session's recv-side FMP state to its assigned
    /// worker. Called when a session is promoted or rekeyed; the worker
    /// thereafter is the sole authority over the FMP replay window and
    /// recv cipher clone for this session.
    ///
    /// Returns `true` iff the registration message was actually
    /// queued. Callers MUST gate any "this session is now worker-
    /// owned" state on the returned bool — the previous version
    /// fire-and-forget'd the `try_send` and the caller unconditionally
    /// marked the session as registered on its side, so under
    /// sustained queue pressure rx_loop believed the worker owned a
    /// session that had never received the cipher + replay state.
    /// Subsequent `dispatch_job` packets then arrived at a worker
    /// shard without that session in its local `HashMap` and were
    /// silently dropped (the "session unregistered mid-flight"
    /// fallback path in `handle_job`). The caller's normal retry —
    /// "re-register on a later event" — is documented at the only
    /// call site (`register_decrypt_worker_session`).
    #[must_use = "registration may have failed under queue pressure; caller must gate its own session-registered flag on the returned bool"]
    pub fn register_session(
        &self,
        session_key: DecryptSessionKey,
        mut state: OwnedSessionState,
    ) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for(session_key);
        let shared = self
            .fmp_preowner_aead_helpers_enabled()
            .then(|| Arc::new(state.shared_crypto_session(idx)));
        if let Some(shared) = &shared {
            state.attach_shared_crypto_session(Arc::clone(shared));
        }
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::RegisterSession { session_key, state })
        {
            Ok(()) => {
                if let Ok(mut sessions) = self.fmp_aead_sessions.write() {
                    if let Some(shared) = shared {
                        sessions.insert(session_key, shared);
                    } else {
                        sessions.remove(&session_key);
                    }
                }
                true
            }
            Err(TrySendError::Full(_)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerQueueFull,
                );
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerRegisterFull,
                );
                warn!(
                    worker = idx,
                    "DecryptWorker channel full at session registration; will retry on next packet"
                );
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring registration"
                );
                false
            }
        }
    }

    #[must_use = "registration may have failed under queue pressure"]
    pub fn register_fsp_session(
        &self,
        source_addr: NodeAddr,
        state: FspRecvSessionSnapshot,
    ) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for_fsp(&source_addr);
        let state = OwnedFspSessionState::from(state);
        let shared = self
            .fsp_shared_crypto_enabled()
            .then(|| state.shared_crypto_session(idx))
            .flatten()
            .map(Arc::new);
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::RegisterFspSession { source_addr, state })
        {
            Ok(()) => {
                if let Ok(mut sessions) = self.fsp_aead_sessions.write() {
                    if let Some(shared) = shared {
                        sessions.insert(source_addr, shared);
                    } else {
                        sessions.remove(&source_addr);
                    }
                }
                true
            }
            Err(TrySendError::Full(_)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerQueueFull,
                );
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerRegisterFull,
                );
                warn!(
                    worker = idx,
                    "DecryptWorker channel full at FSP session registration; rx-loop fallback remains available"
                );
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring FSP registration"
                );
                false
            }
        }
    }

    fn fsp_shared_crypto_enabled(&self) -> bool {
        self.fsp_aead_helpers_enabled() || self.fmp_preowner_fsp_fusion_enabled()
    }

    pub fn unregister_fsp_session(&self, source_addr: NodeAddr) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for_fsp(&source_addr);
        if let Ok(mut sessions) = self.fsp_aead_sessions.write() {
            sessions.remove(&source_addr);
        }
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::UnregisterFspSession { source_addr })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_priority_drop(idx, "unregister-fsp");
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring FSP unregister"
                );
                false
            }
        }
    }

    /// Drop a session from its worker (rekey, peer removed).
    ///
    /// Returns `true` iff the unregister control message reached the worker's
    /// bounded priority lane. A full priority lane is still non-blocking, but
    /// it records visible pressure instead of silently hiding stale
    /// worker-owned session state.
    pub fn unregister_session(&self, session_key: DecryptSessionKey) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for(session_key);
        if let Ok(mut sessions) = self.fmp_aead_sessions.write() {
            sessions.remove(&session_key);
        }
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::UnregisterSession { session_key })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_priority_drop(idx, "unregister");
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring unregister"
                );
                false
            }
        }
    }
}
