/// Handle to the decrypt worker pool. Shard-style: each worker is one
/// OS thread that owns its sessions outright. Dispatch is
/// deterministic on `session_key` so a session always reaches the same
/// shard.
#[derive(Clone)]
pub(crate) struct DecryptWorkerPool {
    senders: Arc<[DecryptWorkerSender]>,
    direct_delivery_sink: DecryptDirectSessionDeliverySink,
}

#[derive(Clone)]
struct DecryptWorkerSender {
    priority: Sender<WorkerMsg>,
    bulk: Sender<DecryptWorkerBulkItem>,
    bulk_queued_packets: Arc<AtomicUsize>,
    bulk_packet_cap: usize,
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
            let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
            receivers.push((priority_rx, bulk_rx, Arc::clone(&bulk_queued_packets)));
            senders.push(DecryptWorkerSender {
                priority: priority_tx,
                bulk: bulk_tx,
                bulk_queued_packets,
                bulk_packet_cap: bulk_channel_cap,
            });
        }
        let pool = Self {
            senders: senders.into(),
            direct_delivery_sink,
        };
        for (i, (priority_rx, bulk_rx, worker_bulk_queued_packets)) in
            receivers.into_iter().enumerate()
        {
            let worker_pool = pool.clone();
            std::thread::Builder::new()
                .name(format!("fips-decrypt-{i}"))
                .spawn(move || {
                    run_worker(
                        i,
                        worker_pool,
                        priority_rx,
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
        state: OwnedSessionState,
    ) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for(session_key);
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::RegisterSession { session_key, state })
        {
            Ok(()) => true,
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
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::RegisterFspSession { source_addr, state })
        {
            Ok(()) => true,
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

    pub fn unregister_fsp_session(&self, source_addr: NodeAddr) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for_fsp(&source_addr);
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
