/// Handle to the decrypt worker pool. Shard-style: each worker is one
/// OS thread that owns its sessions outright. FMP dispatch follows the
/// registered owner for the session key, falling back to the old session-key
/// hash only before registration has reached the pool.
#[derive(Clone)]
pub(crate) struct DecryptWorkerPool {
    senders: Arc<[DecryptWorkerSender]>,
    direct_delivery_sink: DecryptDirectSessionDeliverySink,
    fallback_tx: DecryptWorkerFallbackSender,
    fmp_session_owners: Arc<RwLock<HashMap<DecryptSessionKey, usize>>>,
    fsp_aead_sessions: Arc<RwLock<HashMap<NodeAddr, Arc<FspSharedCryptoSession>>>>,
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
        DecryptWorkerBulkItem::Job(_) | DecryptWorkerBulkItem::Batch(_) => {
            DecryptWorkerBulkQueueRole::FmpBulk
        }
        DecryptWorkerBulkItem::FspJob(_) | DecryptWorkerBulkItem::FspBatch(_) => {
            DecryptWorkerBulkQueueRole::FspOwner
        }
        DecryptWorkerBulkItem::FspAeadOpen(_) | DecryptWorkerBulkItem::FspAeadOpenBatch(_) => {
            DecryptWorkerBulkQueueRole::FspOpen
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
            fmp_session_owners: Arc::new(RwLock::new(HashMap::new())),
            fsp_aead_sessions: Arc::new(RwLock::new(HashMap::new())),
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

    /// Stable hash from session key → worker index. Same hash is used
    /// for session registration and per-packet dispatch so packets and
    /// registration arrive at the same shard.
    fn worker_idx_for(&self, session_key: DecryptSessionKey) -> usize {
        (decrypt_session_fast_hash(session_key) as usize) % self.senders.len()
    }

    fn worker_idx_for_fsp(&self, source_addr: &NodeAddr) -> usize {
        (decrypt_fsp_session_fast_hash(source_addr) as usize) % self.senders.len()
    }

    fn registered_fmp_session_owner(&self, session_key: DecryptSessionKey) -> Option<usize> {
        self.fmp_session_owners
            .read()
            .ok()
            .and_then(|owners| owners.get(&session_key).copied())
            .filter(|idx| *idx < self.senders.len())
    }

    fn worker_idx_for_new_fmp_session(
        &self,
        _session_key: DecryptSessionKey,
        source_peer: &PeerIdentity,
    ) -> usize {
        self.worker_idx_for_fsp(source_peer.node_addr())
    }

    fn worker_idx_for_fmp_session(&self, session_key: DecryptSessionKey) -> usize {
        self.registered_fmp_session_owner(session_key)
            .unwrap_or_else(|| self.worker_idx_for(session_key))
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

    fn worker_idx_for_fsp_open_avoiding_pair(
        &self,
        source_addr: &NodeAddr,
        first_avoid_idx: usize,
        second_avoid_idx: usize,
    ) -> Option<usize> {
        if first_avoid_idx == second_avoid_idx {
            return self.worker_idx_for_fsp_open_avoiding(source_addr, first_avoid_idx);
        }
        let worker_count = self.senders.len();
        if worker_count <= 2 || first_avoid_idx >= worker_count || second_avoid_idx >= worker_count
        {
            return None;
        }

        let mut pick = (decrypt_fsp_open_worker_fast_hash(source_addr) as usize) % (worker_count - 2);
        for idx in 0..worker_count {
            if idx == first_avoid_idx || idx == second_avoid_idx {
                continue;
            }
            if pick == 0 {
                return Some(idx);
            }
            pick -= 1;
        }
        None
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
        self.dispatch_bulk_item(idx, DecryptWorkerBulkItem::Job(job));
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

    fn fsp_aead_session(&self, source_addr: &NodeAddr) -> Option<Arc<FspSharedCryptoSession>> {
        self.fsp_aead_sessions
            .read()
            .ok()
            .and_then(|sessions| sessions.get(source_addr).cloned())
    }

    fn publish_fsp_aead_session(
        &self,
        source_addr: NodeAddr,
        shared: Option<Arc<FspSharedCryptoSession>>,
    ) {
        if let Ok(mut sessions) = self.fsp_aead_sessions.write() {
            if let Some(shared) = shared {
                sessions.insert(source_addr, shared);
            } else {
                sessions.remove(&source_addr);
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_fsp_aead_open_worker_job(
        &self,
        open_idx: usize,
        owner_idx: usize,
        job: FspAeadOpenJob,
    ) -> Result<(), FspAeadOpenJob> {
        self.dispatch_fsp_aead_open_decrypt_worker_job(open_idx, owner_idx, job)
    }

    #[allow(clippy::result_large_err)]
    fn dispatch_fsp_aead_open_decrypt_worker_job(
        &self,
        open_idx: usize,
        owner_idx: usize,
        mut job: FspAeadOpenJob,
    ) -> Result<(), FspAeadOpenJob> {
        let Some(open_sender) = self.senders.get(open_idx) else {
            return Err(job);
        };
        if self.senders.get(owner_idx).is_none() {
            return Err(job);
        }
        job.completion_owner_idx = Some(owner_idx);
        job.open_queued_at = crate::perf_profile::stamp();
        if !try_reserve_bulk_packets(
            &open_sender.bulk_queued_packets,
            open_sender.bulk_packet_cap,
            1,
        ) {
            record_decrypt_fsp_bulk_queue_full_fallback_count(1);
            return Err(job);
        }

        match open_sender
            .bulk
            .try_send(DecryptWorkerBulkItem::FspAeadOpen(job))
        {
            Ok(()) => {
                record_decrypt_worker_bulk_queue_depth(
                    open_sender,
                    1,
                    DecryptWorkerBulkQueueRole::FspOpen,
                );
                Ok(())
            }
            Err(TrySendError::Full(DecryptWorkerBulkItem::FspAeadOpen(job))) => {
                release_bulk_packets(&open_sender.bulk_queued_packets, 1);
                record_decrypt_fsp_bulk_queue_full_fallback_count(1);
                Err(job)
            }
            Err(TrySendError::Disconnected(DecryptWorkerBulkItem::FspAeadOpen(job))) => {
                release_bulk_packets(&open_sender.bulk_queued_packets, 1);
                debug!(
                    worker = open_idx,
                    "DecryptWorker opener thread gone; completing FSP open inline"
                );
                Err(job)
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                unreachable!("FSP AEAD opener dispatch only sends FspAeadOpen jobs")
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

        if jobs.len() == 1 {
            let job = jobs.pop().expect("checked non-empty opener batch");
            return self
                .dispatch_fsp_aead_open_decrypt_worker_job(open_idx, owner_idx, job)
                .map_err(|job| vec![job]);
        }

        let Some(open_sender) = self.senders.get(open_idx) else {
            return Err(jobs);
        };
        if self.senders.get(owner_idx).is_none() {
            return Err(jobs);
        };
        let queued_at = crate::perf_profile::stamp();
        for job in &mut jobs {
            job.completion_owner_idx = Some(owner_idx);
            job.open_queued_at = queued_at;
        }

        let packet_count = jobs.len();
        let reserved_packets = try_reserve_bulk_packets_partial(
            &open_sender.bulk_queued_packets,
            open_sender.bulk_packet_cap,
            packet_count,
        );
        if reserved_packets == 0 {
            record_decrypt_fsp_bulk_queue_full_fallback_count(packet_count);
            return Err(jobs);
        }

        let overflow = if reserved_packets < packet_count {
            Some(jobs.split_off(reserved_packets))
        } else {
            None
        };
        let reserved_item = decrypt_worker_bulk_item_from_fsp_aead_open_jobs(jobs);

        match open_sender.bulk.try_send(reserved_item) {
            Ok(()) => {
                record_decrypt_worker_bulk_queue_depth(
                    open_sender,
                    reserved_packets,
                    DecryptWorkerBulkQueueRole::FspOpen,
                );
                match overflow {
                    Some(overflow) => {
                        record_decrypt_fsp_bulk_queue_full_fallback_count(overflow.len());
                        Err(overflow)
                    }
                    None => Ok(()),
                }
            }
            Err(TrySendError::Full(item)) => {
                release_bulk_packets(&open_sender.bulk_queued_packets, reserved_packets);
                let mut returned = fsp_aead_open_jobs_from_decrypt_worker_bulk_item(item);
                if let Some(overflow) = overflow {
                    returned.extend(overflow);
                }
                record_decrypt_fsp_bulk_queue_full_fallback_count(returned.len());
                Err(returned)
            }
            Err(TrySendError::Disconnected(item)) => {
                release_bulk_packets(&open_sender.bulk_queued_packets, reserved_packets);
                let mut returned = fsp_aead_open_jobs_from_decrypt_worker_bulk_item(item);
                if let Some(overflow) = overflow {
                    returned.extend(overflow);
                }
                debug!(
                    worker = open_idx,
                    "DecryptWorker opener thread gone; completing FSP open batch inline"
                );
                Err(returned)
            }
        }
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
            record_decrypt_fsp_bulk_queue_full_fallback_count(1);
            return Err(job);
        }

        match sender.bulk.try_send(DecryptWorkerBulkItem::FspJob(job)) {
            Ok(()) => {
                record_decrypt_worker_bulk_queue_depth(
                    sender,
                    1,
                    DecryptWorkerBulkQueueRole::FspOwner,
                );
                Ok(())
            }
            Err(TrySendError::Full(DecryptWorkerBulkItem::FspJob(job))) => {
                release_bulk_packets(&sender.bulk_queued_packets, 1);
                record_decrypt_fsp_bulk_queue_full_fallback_count(1);
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
        let reserved_packets = try_reserve_bulk_packets_partial(
            &sender.bulk_queued_packets,
            sender.bulk_packet_cap,
            packet_count,
        );
        if reserved_packets == 0 {
            record_decrypt_fsp_bulk_queue_full_fallback_count(packet_count);
            return Err(jobs);
        }

        let overflow = if reserved_packets < packet_count {
            Some(jobs.split_off(reserved_packets))
        } else {
            None
        };
        let reserved_item = decrypt_worker_bulk_item_from_fsp_jobs(jobs);

        match sender.bulk.try_send(reserved_item) {
            Ok(()) => {
                record_decrypt_worker_bulk_queue_depth(
                    sender,
                    reserved_packets,
                    DecryptWorkerBulkQueueRole::FspOwner,
                );
                match overflow {
                    Some(overflow) => {
                        record_decrypt_fsp_bulk_queue_full_fallback_count(overflow.len());
                        Err(overflow)
                    }
                    None => Ok(()),
                }
            }
            Err(TrySendError::Full(item)) => {
                release_bulk_packets(&sender.bulk_queued_packets, reserved_packets);
                let mut returned = fsp_jobs_from_decrypt_worker_bulk_item(item);
                if let Some(overflow) = overflow {
                    returned.extend(overflow);
                }
                record_decrypt_fsp_bulk_queue_full_fallback_count(returned.len());
                Err(returned)
            }
            Err(TrySendError::Disconnected(item)) => {
                release_bulk_packets(&sender.bulk_queued_packets, reserved_packets);
                let mut returned = fsp_jobs_from_decrypt_worker_bulk_item(item);
                if let Some(overflow) = overflow {
                    returned.extend(overflow);
                }
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; falling FSP bulk job batch back to rx_loop"
                );
                Err(returned)
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
        let reserved_packets = try_reserve_bulk_packets_partial(
            &sender.bulk_queued_packets,
            sender.bulk_packet_cap,
            packet_count,
        );
        if reserved_packets == 0 {
            record_decrypt_worker_bulk_drop_count(idx, packet_count);
            return Err(item);
        }

        let (reserved_item, overflow_item) = item.split_at_packet_count(reserved_packets);
        let reserved_item = reserved_item.expect("positive reservation must produce a bulk item");
        let role = crate::perf_profile::enabled()
            .then(|| decrypt_worker_bulk_queue_role(&reserved_item));

        match sender.bulk.try_send(reserved_item) {
            Ok(()) => {
                if let Some(role) = role {
                    record_decrypt_worker_bulk_queue_depth(sender, reserved_packets, role);
                }
                if let Some(overflow_item) = overflow_item {
                    record_decrypt_worker_bulk_drop_count(idx, overflow_item.packet_count());
                    Err(overflow_item)
                } else {
                    Ok(())
                }
            }
            Err(TrySendError::Full(item)) => {
                release_bulk_packets(&sender.bulk_queued_packets, reserved_packets);
                record_decrypt_worker_bulk_drop_count(idx, reserved_packets);
                if let Some(overflow_item) = overflow_item {
                    record_decrypt_worker_bulk_drop_count(idx, overflow_item.packet_count());
                }
                Err(item)
            }
            Err(TrySendError::Disconnected(item)) => {
                release_bulk_packets(&sender.bulk_queued_packets, reserved_packets);
                debug!(worker = idx, "DecryptWorker thread gone; dropping bulk job");
                if let Some(overflow_item) = overflow_item {
                    record_decrypt_worker_bulk_drop_count(idx, overflow_item.packet_count());
                }
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
    ) -> Option<usize> {
        if self.senders.is_empty() {
            return None;
        }
        let idx = self.registered_fmp_session_owner(session_key).unwrap_or_else(|| {
            self.worker_idx_for_new_fmp_session(session_key, &state.source_peer)
        });
        match self.senders[idx]
            .control
            .try_send(WorkerMsg::RegisterSession { session_key, state })
        {
            Ok(()) => {
                if let Ok(mut owners) = self.fmp_session_owners.write() {
                    owners.insert(session_key, idx);
                }
                Some(idx)
            }
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

    /// Drop the shared FSP opener state only after the owner worker accepts the
    /// bounded unregister control message. A full control lane means the worker
    /// still owns that receive state, so callers must treat `false` as pressure.
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
            Ok(()) => {
                if let Ok(mut sessions) = self.fsp_aead_sessions.write() {
                    sessions.remove(&source_addr);
                }
                true
            }
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_control_drop(idx, "unregister-fsp");
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                if let Ok(mut sessions) = self.fsp_aead_sessions.write() {
                    sessions.remove(&source_addr);
                }
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
    pub fn unregister_session(&self, session_key: DecryptSessionKey) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for_fmp_session(session_key);
        match self.senders[idx]
            .control
            .try_send(WorkerMsg::UnregisterSession { session_key })
        {
            Ok(()) => {
                if let Ok(mut owners) = self.fmp_session_owners.write() {
                    owners.remove(&session_key);
                }
                true
            }
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_control_drop(idx, "unregister");
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                if let Ok(mut owners) = self.fmp_session_owners.write() {
                    owners.remove(&session_key);
                }
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring unregister"
                );
                false
            }
        }
    }
}
