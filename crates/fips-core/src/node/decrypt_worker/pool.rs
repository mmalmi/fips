/// Handle to the decrypt worker pool. Shard-style: each worker is one
/// OS thread that owns its sessions outright. FMP dispatch follows the
/// registered owner for the session key, falling back to the old session-key
/// hash only before registration has reached the pool.
#[derive(Clone)]
pub(crate) struct DecryptWorkerPool {
    senders: Arc<[DecryptWorkerSender]>,
    direct_delivery_sink: DecryptDirectSessionDeliverySink,
    fallback_tx: DecryptWorkerFallbackSender,
}

#[derive(Clone)]
struct DecryptWorkerSender {
    control: Sender<WorkerMsg>,
    priority: Sender<WorkerMsg>,
    bulk: Sender<DecryptWorkerBulkItem>,
    fsp_aead_completion: Sender<FspAeadCompletionBatch>,
    bulk_queued_packets: Arc<AtomicUsize>,
    bulk_packet_cap: usize,
}

#[derive(Clone, Copy)]
enum DecryptWorkerBulkQueueRole {
    FmpBulk,
    FspOwner,
    FspOpen,
}

struct BulkQueueSendError {
    item: DecryptWorkerBulkItem,
    overflow: Option<DecryptWorkerBulkItem>,
    disconnected: bool,
}

fn record_decrypt_fsp_bulk_queue_full_fallback_count(count: usize) {
    if count == 0 {
        return;
    }
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptWorkerQueueFull,
        count as u64,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspBulkQueueFullFallback,
        count as u64,
    );
}

fn record_decrypt_worker_bulk_queue_depth(
    sender: &DecryptWorkerSender,
    packets: usize,
    role: DecryptWorkerBulkQueueRole,
) {
    if !crate::perf_profile::enabled() || packets == 0 {
        return;
    }
    let depth = sender.bulk_queued_packets.load(Ordering::Relaxed);
    crate::perf_profile::record_decrypt_worker_bulk_queue_depth(
        depth,
        sender.bulk_packet_cap,
        packets,
    );
    match role {
        DecryptWorkerBulkQueueRole::FmpBulk => {
            crate::perf_profile::record_decrypt_worker_fmp_bulk_queue_depth(depth, packets);
        }
        DecryptWorkerBulkQueueRole::FspOwner => {
            crate::perf_profile::record_decrypt_worker_fsp_owner_queue_depth(depth, packets);
        }
        DecryptWorkerBulkQueueRole::FspOpen => {
            crate::perf_profile::record_decrypt_worker_fsp_open_queue_depth(depth, packets);
        }
    }
}

fn decrypt_worker_bulk_queue_role(item: &DecryptWorkerBulkItem) -> DecryptWorkerBulkQueueRole {
    match item {
        DecryptWorkerBulkItem::Batch(_) => DecryptWorkerBulkQueueRole::FmpBulk,
        DecryptWorkerBulkItem::FspBatch(_) => DecryptWorkerBulkQueueRole::FspOwner,
        DecryptWorkerBulkItem::FspAeadOpenBatch(_) => DecryptWorkerBulkQueueRole::FspOpen,
    }
}

fn try_send_bulk_item_prefix(
    sender: &DecryptWorkerSender,
    item: DecryptWorkerBulkItem,
) -> Result<(usize, Option<DecryptWorkerBulkItem>), BulkQueueSendError> {
    let packet_count = item.packet_count();
    let reserved_packets = try_reserve_bulk_packets_partial(
        &sender.bulk_queued_packets,
        sender.bulk_packet_cap,
        packet_count,
    );
    if reserved_packets == 0 {
        return Err(BulkQueueSendError {
            item,
            overflow: None,
            disconnected: false,
        });
    }

    let (reserved_item, overflow) = item.split_at_packet_count(reserved_packets);
    let reserved_item = reserved_item.expect("positive reservation must produce a bulk item");

    match sender.bulk.try_send(reserved_item) {
        Ok(()) => Ok((reserved_packets, overflow)),
        Err(TrySendError::Full(item)) => {
            release_bulk_packets(&sender.bulk_queued_packets, reserved_packets);
            Err(BulkQueueSendError {
                item,
                overflow,
                disconnected: false,
            })
        }
        Err(TrySendError::Disconnected(item)) => {
            release_bulk_packets(&sender.bulk_queued_packets, reserved_packets);
            Err(BulkQueueSendError {
                item,
                overflow,
                disconnected: true,
            })
        }
    }
}

fn record_decrypt_worker_control_drop(worker: usize, kind: &'static str) {
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerQueueFull);
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerControlDropped);
    static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = FULL_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(10000) {
        warn!(
            worker,
            kind,
            drops = n + 1,
            "DecryptWorker control channel full; dropping control item"
        );
    }
}

impl DecryptWorkerPool {
    #[cfg(test)]
    pub(crate) fn spawn(n: usize) -> Self {
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels();
        Self::spawn_with_direct_delivery_sink(
            n,
            DecryptDirectSessionDeliverySink::default(),
            fallback_tx,
        )
    }

    pub(crate) fn spawn_with_direct_delivery_sink(
        n: usize,
        direct_delivery_sink: DecryptDirectSessionDeliverySink,
        fallback_tx: DecryptWorkerFallbackSender,
    ) -> Self {
        let n = n.max(1);
        let bulk_channel_cap = bulk_channel_cap();
        let control_channel_cap = control_channel_cap();
        let priority_channel_cap = priority_channel_cap();
        let mut senders = Vec::with_capacity(n);
        let mut receivers = Vec::with_capacity(n);
        for _ in 0..n {
            let (control_tx, control_rx) = bounded::<WorkerMsg>(control_channel_cap);
            let (priority_tx, priority_rx) = bounded::<WorkerMsg>(priority_channel_cap);
            let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(bulk_channel_cap);
            let (fsp_aead_completion_tx, fsp_aead_completion_rx) =
                bounded::<FspAeadCompletionBatch>(
                    fsp_aead_completion_channel_cap_from_bulk_cap(bulk_channel_cap),
                );
            let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
            receivers.push((
                control_rx,
                priority_rx,
                fsp_aead_completion_rx,
                bulk_rx,
                Arc::clone(&bulk_queued_packets),
            ));
            senders.push(DecryptWorkerSender {
                control: control_tx,
                priority: priority_tx,
                bulk: bulk_tx,
                fsp_aead_completion: fsp_aead_completion_tx,
                bulk_queued_packets,
                bulk_packet_cap: bulk_channel_cap,
            });
        }
        let pool = Self {
            senders: senders.into(),
            direct_delivery_sink,
            fallback_tx,
        };
        for (
            i,
            (
                control_rx,
                priority_rx,
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
                        control_rx,
                        priority_rx,
                        fsp_aead_completion_rx,
                        bulk_rx,
                        worker_bulk_queued_packets,
                    )
                })
                .expect("failed to spawn fips-decrypt OS thread");
        }
        pool
    }

    /// Test helper for legacy pre-registration dispatch. Production
    /// registration is source-affine and rx-loop carries the accepted owner.
    #[cfg(test)]
    fn worker_idx_for(&self, session_key: DecryptSessionKey) -> usize {
        (decrypt_session_fast_hash(session_key) as usize) % self.senders.len()
    }

    fn worker_idx_for_fsp(&self, source_addr: &NodeAddr) -> usize {
        (decrypt_fsp_session_fast_hash(source_addr) as usize) % self.senders.len()
    }

    fn worker_idx_for_new_fmp_session(
        &self,
        _session_key: DecryptSessionKey,
        source_peer: &PeerIdentity,
    ) -> usize {
        self.worker_idx_for_fsp(source_peer.node_addr())
    }

    fn worker_idx_for_fsp_open_avoiding(
        &self,
        source_addr: &NodeAddr,
        avoid_idx: usize,
    ) -> Option<usize> {
        let worker_count = self.senders.len();
        if worker_count <= 1 || avoid_idx >= worker_count {
            return None;
        }
        let mut idx = (decrypt_fsp_open_worker_fast_hash(source_addr) as usize) % (worker_count - 1);
        if idx >= avoid_idx {
            idx += 1;
        }
        Some(idx)
    }

    fn bulk_batch_packet_max_for(&self, idx: usize) -> usize {
        self.senders[idx]
            .bulk_packet_cap
            .clamp(1, DECRYPT_WORKER_BULK_BATCH_MAX)
    }

    fn fsp_open_batch_packet_max_for(&self, idx: usize) -> usize {
        self.bulk_batch_packet_max_for(idx)
    }

    /// Dispatch a per-packet decrypt job. Priority jobs get a bounded
    /// fast lane first; if that lane is saturated, fall back to the
    /// bulk lane rather than dropping already-authenticated liveness
    /// or small-session traffic during transient ACK-heavy bursts.
    pub fn dispatch_job(&self, mut job: DecryptJob) {
        if self.senders.is_empty() {
            return;
        }
        job.set_trace_enqueued_at(crate::perf_profile::stamp());
        let idx = job.worker_idx();
        if idx >= self.senders.len() {
            record_decrypt_worker_bulk_drop_count(idx, 1);
            return;
        }
        match decrypt_job_lane(&job) {
            DecryptWorkerLane::Priority => self.dispatch_priority_job(idx, job),
            DecryptWorkerLane::Bulk => self.dispatch_bulk_job(idx, job),
        }
    }

    fn dispatch_priority_job(&self, idx: usize, job: DecryptJob) {
        match self.senders[idx].priority.try_send(WorkerMsg::Job(job)) {
            Ok(()) => {}
            Err(TrySendError::Full(WorkerMsg::Job(job))) => {
                self.dispatch_bulk_job(idx, job);
            }
            Err(TrySendError::Full(_)) => unreachable!("priority dispatch only sends jobs"),
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; dropping priority job"
                );
            }
        }
    }

    fn dispatch_bulk_job(&self, idx: usize, job: DecryptJob) {
        self.dispatch_bulk_item(idx, decrypt_worker_bulk_item_from_jobs(vec![job]));
    }

    fn fsp_bulk_open_worker_enabled(&self) -> bool {
        self.senders.len() > 1
    }

    fn send_fsp_aead_completion_batch(
        &self,
        owner_idx: usize,
        batch: FspAeadCompletionBatch,
    ) -> bool {
        self.senders
            .get(owner_idx)
            .is_some_and(|sender| sender.fsp_aead_completion.send(batch).is_ok())
    }

    fn dispatch_fsp_bulk_jobs_or_return<T>(
        &self,
        idx: usize,
        jobs: Vec<T>,
        role: DecryptWorkerBulkQueueRole,
        item_from_jobs: fn(Vec<T>) -> DecryptWorkerBulkItem,
        jobs_from_item: fn(DecryptWorkerBulkItem) -> Vec<T>,
    ) -> Result<(), Vec<T>> {
        debug_assert!(!jobs.is_empty());
        debug_assert!(jobs.len() <= DECRYPT_WORKER_BULK_BATCH_MAX);

        let Some(sender) = self.senders.get(idx) else {
            return Err(jobs);
        };
        match try_send_bulk_item_prefix(sender, item_from_jobs(jobs)) {
            Ok((reserved_packets, overflow)) => {
                record_decrypt_worker_bulk_queue_depth(sender, reserved_packets, role);
                match overflow {
                    Some(item) => {
                        let jobs = jobs_from_item(item);
                        record_decrypt_fsp_bulk_queue_full_fallback_count(jobs.len());
                        Err(jobs)
                    }
                    None => Ok(()),
                }
            }
            Err(err) => {
                let disconnected = err.disconnected;
                let mut returned = jobs_from_item(err.item);
                if let Some(overflow) = err.overflow {
                    returned.extend(jobs_from_item(overflow));
                }
                if disconnected {
                    debug!(
                        worker = idx,
                        "DecryptWorker FSP bulk thread gone; returning worker-owned jobs"
                    );
                } else {
                    record_decrypt_fsp_bulk_queue_full_fallback_count(returned.len());
                }
                Err(returned)
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_fsp_aead_open_worker_job_batch_or_return(
        &self,
        open_idx: usize,
        owner_idx: usize,
        mut jobs: Vec<FspAeadOpenJob>,
    ) -> Result<(), Vec<FspAeadOpenJob>> {
        debug_assert!(!jobs.is_empty());
        debug_assert!(jobs.len() <= DECRYPT_WORKER_BULK_BATCH_MAX);

        if self.senders.get(owner_idx).is_none() {
            return Err(jobs);
        };
        let queued_at = crate::perf_profile::stamp();
        for job in &mut jobs {
            job.completion_owner_idx = Some(owner_idx);
            job.open_queued_at = queued_at;
        }

        self.dispatch_fsp_bulk_jobs_or_return(
            open_idx,
            jobs,
            DecryptWorkerBulkQueueRole::FspOpen,
            decrypt_worker_bulk_item_from_fsp_aead_open_jobs,
            fsp_aead_open_jobs_from_decrypt_worker_bulk_item,
        )
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_bulk_fsp_job_or_return(
        &self,
        idx: usize,
        job: FspDecryptJob,
    ) -> Result<(), FspDecryptJob> {
        self.dispatch_bulk_fsp_job_batch_or_return(idx, vec![job])
            .map_err(|mut jobs| {
                debug_assert_eq!(jobs.len(), 1);
                jobs.pop().expect("single FSP job dispatch returned empty batch")
            })
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

        self.dispatch_fsp_bulk_jobs_or_return(
            idx,
            jobs,
            DecryptWorkerBulkQueueRole::FspOwner,
            decrypt_worker_bulk_item_from_fsp_jobs,
            fsp_jobs_from_decrypt_worker_bulk_item,
        )
    }

    fn dispatch_bulk_job_batch(&self, idx: usize, mut jobs: Vec<DecryptJob>) {
        debug_assert!(!jobs.is_empty());
        debug_assert!(jobs.len() <= DECRYPT_WORKER_BULK_BATCH_MAX);
        debug_assert!(jobs.iter().all(DecryptJob::is_bulk_lane));

        let queued_at = crate::perf_profile::stamp();
        for job in &mut jobs {
            job.set_trace_enqueued_at(queued_at);
        }

        self.dispatch_bulk_item(idx, decrypt_worker_bulk_item_from_jobs(jobs));
    }

    fn dispatch_bulk_item(&self, idx: usize, item: DecryptWorkerBulkItem) {
        let sender = &self.senders[idx];
        let role =
            crate::perf_profile::enabled().then(|| decrypt_worker_bulk_queue_role(&item));
        match try_send_bulk_item_prefix(sender, item) {
            Ok((reserved_packets, overflow_item)) => {
                if let Some(role) = role {
                    record_decrypt_worker_bulk_queue_depth(sender, reserved_packets, role);
                }
                if let Some(overflow_item) = overflow_item {
                    record_decrypt_worker_bulk_drop_count(idx, overflow_item.packet_count());
                }
            }
            Err(err) => {
                let BulkQueueSendError {
                    item,
                    overflow,
                    disconnected,
                } = err;
                if disconnected {
                    debug!(worker = idx, "DecryptWorker thread gone; dropping bulk job");
                    if let Some(overflow_item) = &overflow {
                        record_decrypt_worker_bulk_drop_count(idx, overflow_item.packet_count());
                    }
                } else {
                    record_decrypt_worker_bulk_drop_count(
                        idx,
                        item.packet_count()
                            + overflow
                                .as_ref()
                                .map_or(0, DecryptWorkerBulkItem::packet_count),
                    );
                }
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
    ) -> Option<usize> {
        if self.senders.is_empty() {
            return None;
        }
        let idx = self.worker_idx_for_new_fmp_session(session_key, &state.source_peer);
        match self.senders[idx]
            .control
            .try_send(WorkerMsg::RegisterSession { session_key, state })
        {
            Ok(()) => Some(idx),
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_control_drop(idx, "register");
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerRegisterFull,
                );
                warn!(
                    worker = idx,
                    "DecryptWorker channel full at session registration; will retry on next packet"
                );
                None
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring registration"
                );
                None
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
            .control
            .try_send(WorkerMsg::RegisterFspSession { source_addr, state })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_control_drop(idx, "register-fsp");
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

    /// Drop FSP receive state only after the owner worker accepts the bounded
    /// unregister control message. A full control lane means the worker still
    /// owns that receive state, so callers must treat `false` as pressure.
    #[must_use = "unregistration may have failed under queue pressure"]
    pub fn unregister_fsp_session(&self, source_addr: NodeAddr) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for_fsp(&source_addr);
        match self.senders[idx]
            .control
            .try_send(WorkerMsg::UnregisterFspSession { source_addr })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_control_drop(idx, "unregister-fsp");
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
    /// bounded control lane. A full control lane is still non-blocking, but it
    /// records visible pressure instead of silently hiding stale worker-owned
    /// session state.
    pub fn unregister_session(&self, session_key: DecryptSessionKey, owner_idx: usize) -> bool {
        if self.senders.is_empty() || owner_idx >= self.senders.len() {
            return false;
        }
        match self.senders[owner_idx]
            .control
            .try_send(WorkerMsg::UnregisterSession { session_key })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_control_drop(owner_idx, "unregister");
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = owner_idx,
                    "DecryptWorker thread gone; ignoring unregister"
                );
                false
            }
        }
    }
}
