/// Messages travelling through the per-worker crossbeam channel.
/// `Job` is the per-packet hot path; `RegisterSession` /
/// `UnregisterSession` are control plane events sent at session
/// establishment / teardown.
///
/// The `Job` variant is intentionally much larger than the control
/// variants (it carries the whole packet buffer + cipher clone). The
/// alternative — boxing `Job` — adds a per-packet alloc on the hot
/// path, which is the exact thing this module is designed to avoid.
#[allow(clippy::large_enum_variant)]
enum WorkerMsg {
    Job(DecryptJob),
    RegisterSession {
        session_key: DecryptSessionKey,
        state: OwnedSessionState,
    },
    RegisterFspSession {
        source_addr: NodeAddr,
        state: OwnedFspSessionState,
    },
    UnregisterSession {
        session_key: DecryptSessionKey,
    },
    UnregisterFspSession {
        source_addr: NodeAddr,
    },
}

#[allow(clippy::large_enum_variant)]
enum DecryptWorkerBulkItem {
    FspAeadOpenBatch(Vec<FspAeadOpenDispatch>),
    Batch {
        session_key: DecryptSessionKey,
        jobs: Vec<DecryptJob>,
    },
    FspBatch(Vec<FspDecryptJob>),
}

impl DecryptWorkerBulkItem {
    fn packet_count(&self) -> usize {
        match self {
            Self::FspAeadOpenBatch(jobs) => jobs.len(),
            Self::Batch { jobs, .. } => jobs.len(),
            Self::FspBatch(jobs) => jobs.len(),
        }
    }

    fn split_at_packet_count(
        self,
        packet_count: usize,
    ) -> (Option<DecryptWorkerBulkItem>, Option<DecryptWorkerBulkItem>) {
        if packet_count == 0 {
            return (None, Some(self));
        }
        match self {
            Self::FspAeadOpenBatch(mut jobs) => {
                if packet_count >= jobs.len() {
                    return (Some(Self::FspAeadOpenBatch(jobs)), None);
                }
                let overflow = jobs.split_off(packet_count);
                (
                    Some(decrypt_worker_bulk_item_from_fsp_aead_open_jobs(jobs)),
                    Some(decrypt_worker_bulk_item_from_fsp_aead_open_jobs(overflow)),
                )
            }
            Self::Batch {
                session_key,
                mut jobs,
            } => {
                if packet_count >= jobs.len() {
                    return (Some(Self::Batch { session_key, jobs }), None);
                }
                let overflow = jobs.split_off(packet_count);
                (
                    Some(decrypt_worker_bulk_item_from_jobs(jobs)),
                    Some(decrypt_worker_bulk_item_from_jobs(overflow)),
                )
            }
            Self::FspBatch(mut jobs) => {
                if packet_count >= jobs.len() {
                    return (Some(Self::FspBatch(jobs)), None);
                }
                let overflow = jobs.split_off(packet_count);
                (
                    Some(decrypt_worker_bulk_item_from_fsp_jobs(jobs)),
                    Some(decrypt_worker_bulk_item_from_fsp_jobs(overflow)),
                )
            }
        }
    }
}

impl SplitBulkLaneItem for DecryptWorkerBulkItem {
    fn packet_count(&self) -> usize {
        DecryptWorkerBulkItem::packet_count(self)
    }

    fn split_at_packet_count(
        self,
        packet_count: usize,
    ) -> (Option<DecryptWorkerBulkItem>, Option<DecryptWorkerBulkItem>) {
        DecryptWorkerBulkItem::split_at_packet_count(self, packet_count)
    }
}

fn decrypt_worker_bulk_item_from_fsp_aead_open_jobs(
    jobs: Vec<FspAeadOpenDispatch>,
) -> DecryptWorkerBulkItem {
    debug_assert!(!jobs.is_empty());
    DecryptWorkerBulkItem::FspAeadOpenBatch(jobs)
}

fn decrypt_worker_bulk_item_from_jobs(jobs: Vec<DecryptJob>) -> DecryptWorkerBulkItem {
    debug_assert!(!jobs.is_empty());
    let session_key = jobs[0].session_key();
    debug_assert!(
        jobs.iter().all(|job| job.session_key() == session_key),
        "decrypt worker bulk batches must be grouped by FMP session"
    );
    DecryptWorkerBulkItem::Batch { session_key, jobs }
}

fn decrypt_worker_bulk_item_from_fsp_jobs(jobs: Vec<FspDecryptJob>) -> DecryptWorkerBulkItem {
    debug_assert!(!jobs.is_empty());
    DecryptWorkerBulkItem::FspBatch(jobs)
}

fn fsp_jobs_from_decrypt_worker_bulk_item(item: DecryptWorkerBulkItem) -> Vec<FspDecryptJob> {
    match item {
        DecryptWorkerBulkItem::FspBatch(jobs) => jobs,
        DecryptWorkerBulkItem::FspAeadOpenBatch(_)
        | DecryptWorkerBulkItem::Batch { .. } => unreachable!("bulk FSP dispatch only sends FSP jobs"),
    }
}

fn fsp_aead_open_jobs_from_decrypt_worker_bulk_item(
    item: DecryptWorkerBulkItem,
) -> Vec<FspAeadOpenDispatch> {
    match item {
        DecryptWorkerBulkItem::FspAeadOpenBatch(jobs) => jobs,
        DecryptWorkerBulkItem::Batch { .. } | DecryptWorkerBulkItem::FspBatch(_) => {
            unreachable!("FSP AEAD opener dispatch only sends opener jobs")
        }
    }
}

struct DecryptWorkerBatchStats {
    enabled: bool,
    packets: usize,
    priority_packets: usize,
    bulk_packets: usize,
}

impl Default for DecryptWorkerBatchStats {
    fn default() -> Self {
        Self {
            enabled: crate::perf_profile::enabled(),
            packets: 0,
            priority_packets: 0,
            bulk_packets: 0,
        }
    }
}

impl DecryptWorkerBatchStats {
    #[cfg(test)]
    fn enabled_for_test() -> Self {
        Self {
            enabled: true,
            packets: 0,
            priority_packets: 0,
            bulk_packets: 0,
        }
    }

    fn add_lane(&mut self, lane: DecryptWorkerLane, count: usize) {
        if !self.enabled || count == 0 {
            return;
        }
        self.packets = self.packets.saturating_add(count);
        match lane {
            DecryptWorkerLane::Priority => {
                self.priority_packets = self.priority_packets.saturating_add(count);
            }
            DecryptWorkerLane::Bulk => {
                self.bulk_packets = self.bulk_packets.saturating_add(count);
            }
        }
    }

    fn add_msg(&mut self, msg: &WorkerMsg) {
        if !self.enabled {
            return;
        }
        match msg {
            WorkerMsg::Job(job) => self.add_lane(job.lane(), 1),
            WorkerMsg::RegisterSession { .. }
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {}
        }
    }

    fn add_bulk_item(&mut self, item: &DecryptWorkerBulkItem) {
        if !self.enabled {
            return;
        }
        match item {
            DecryptWorkerBulkItem::FspAeadOpenBatch(jobs) => {
                self.add_lane(DecryptWorkerLane::Bulk, jobs.len());
            }
            DecryptWorkerBulkItem::Batch { jobs, .. } => {
                for job in jobs {
                    self.add_lane(job.lane(), 1);
                }
            }
            DecryptWorkerBulkItem::FspBatch(jobs) => {
                self.add_lane(DecryptWorkerLane::Bulk, jobs.len());
            }
        }
    }

    fn record(&self, worker_idx: usize) {
        if !self.enabled {
            return;
        }
        crate::perf_profile::record_decrypt_worker_batch(
            self.packets,
            self.priority_packets,
            self.bulk_packets,
            DECRYPT_WORKER_BULK_BURST_BUDGET,
        );
        crate::perf_profile::record_decrypt_worker_batch_target(worker_idx, self.packets);
    }
}

struct FspDecryptJob {
    fallback: DecryptFallback,
    lane: DecryptWorkerLane,
    local_node_addr: NodeAddr,
    source_addr: NodeAddr,
    previous_hop_peer: PeerIdentity,
    path_mtu: u16,
    ce_flag: bool,
    inner_timestamp_ms: u32,
    fsp_payload_offset: usize,
    fsp_payload_len: usize,
    trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl FspDecryptJob {
    fn lane(&self) -> DecryptWorkerLane {
        self.lane
    }

    fn set_trace_enqueued_at(&mut self, queued_at: Option<crate::perf_profile::TraceStamp>) {
        self.trace_enqueued_at = queued_at;
    }

    fn record_queue_wait(&self) {
        let queued_at = self.trace_enqueued_at;
        if queued_at.is_none() {
            return;
        }
        let (priority_count, bulk_count) = match self.lane() {
            DecryptWorkerLane::Priority => (1, 0),
            DecryptWorkerLane::Bulk => (0, 1),
        };
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::DecryptFspWorkerQueueWait,
            crate::perf_profile::Stage::DecryptFspWorkerPriorityQueueWait,
            crate::perf_profile::Stage::DecryptFspWorkerBulkQueueWait,
            queued_at,
            1,
            priority_count,
            bulk_count,
        );
    }
}

struct FspDecryptJobMeta {
    source_addr: NodeAddr,
    path_mtu: u16,
    fsp_payload_offset: usize,
    fsp_payload_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecryptJobBatchKey {
    worker_idx: usize,
    session_key: DecryptSessionKey,
}

pub(crate) struct DecryptJobBatcher {
    batcher: WorkerBulkHandoffBatcher<DecryptJobBatchKey, DecryptJob>,
}

impl DecryptJobBatcher {
    pub(crate) fn new() -> Self {
        Self {
            batcher: WorkerBulkHandoffBatcher::new(DECRYPT_WORKER_BULK_BATCH_MAX),
        }
    }

    #[cfg(test)]
    fn pending_buffer_ptr(&self) -> *const DecryptJob {
        self.batcher.pending_buffer_ptr()
    }

    pub(crate) fn push(&mut self, workers: &DecryptWorkerPool, job: DecryptJob) {
        if !job.is_bulk_lane() {
            self.flush(workers);
            workers.dispatch_job(job);
            return;
        }

        let worker_idx = job.worker_idx();
        let session_key = job.session_key();
        let key = DecryptJobBatchKey {
            worker_idx,
            session_key,
        };
        let batch_max = workers.bulk_batch_packet_max_for(worker_idx);
        self.batcher.push_with_single(
            key,
            batch_max,
            job,
            |key, job| dispatch_single_decrypt_job(workers, key, job),
            |key, jobs| dispatch_decrypt_job_batch(workers, key, jobs),
            |returned| {
                debug_assert!(
                    returned.is_empty(),
                    "FMP decrypt dispatch drops at the worker boundary"
                );
            },
        );
    }

    pub(crate) fn flush(&mut self, workers: &DecryptWorkerPool) {
        self.batcher.flush_with_single(
            |key, job| dispatch_single_decrypt_job(workers, key, job),
            |key, jobs| dispatch_decrypt_job_batch(workers, key, jobs),
            |returned| {
                debug_assert!(
                    returned.is_empty(),
                    "FMP decrypt dispatch drops at the worker boundary"
                );
            },
        );
    }
}

fn dispatch_single_decrypt_job(
    workers: &DecryptWorkerPool,
    key: DecryptJobBatchKey,
    job: DecryptJob,
) -> Vec<DecryptJob> {
    debug_assert_eq!(job.worker_idx(), key.worker_idx);
    debug_assert_eq!(job.session_key(), key.session_key);
    debug_assert!(job.is_bulk_lane());

    workers.dispatch_bulk_job(key.worker_idx, job);
    Vec::new()
}

fn dispatch_decrypt_job_batch(
    workers: &DecryptWorkerPool,
    key: DecryptJobBatchKey,
    jobs: Vec<DecryptJob>,
) -> Vec<DecryptJob> {
    debug_assert!(!jobs.is_empty());
    debug_assert!(jobs.iter().all(|job| job.worker_idx() == key.worker_idx));
    debug_assert!(jobs.iter().all(|job| job.session_key() == key.session_key));
    debug_assert!(jobs.iter().all(DecryptJob::is_bulk_lane));

    workers.dispatch_bulk_job_batch(key.worker_idx, jobs);
    Vec::new()
}

struct FspDecryptJobBatcher {
    batcher: WorkerBulkHandoffBatcher<usize, FspDecryptJob>,
}

impl FspDecryptJobBatcher {
    fn new() -> Self {
        Self {
            batcher: WorkerBulkHandoffBatcher::new(DECRYPT_WORKER_BULK_BATCH_MAX),
        }
    }

    fn is_empty(&self) -> bool {
        self.batcher.is_empty()
    }

    fn push_to(&mut self, workers: &DecryptWorkerPool, worker_idx: usize, job: FspDecryptJob) {
        if !matches!(job.lane(), DecryptWorkerLane::Bulk) {
            self.flush(workers);
            crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFspPathFallback);
            drop_fsp_owner_handoff_job(job);
            return;
        }

        let batch_max = workers.bulk_batch_packet_max_for(worker_idx);
        self.batcher.push(
            worker_idx,
            batch_max,
            job,
            |worker_idx, jobs| {
                dispatch_fsp_decrypt_job_batch(workers, worker_idx, jobs)
            },
            drop_returned_fsp_decrypt_jobs,
        );
    }

    fn flush(&mut self, workers: &DecryptWorkerPool) {
        self.batcher.flush(
            |worker_idx, jobs| dispatch_fsp_decrypt_job_batch(workers, worker_idx, jobs),
            drop_returned_fsp_decrypt_jobs,
        );
    }
}

fn dispatch_fsp_decrypt_job_batch(
    workers: &DecryptWorkerPool,
    worker_idx: usize,
    jobs: Vec<FspDecryptJob>,
) -> Vec<FspDecryptJob> {
    debug_assert!(!jobs.is_empty());
    debug_assert!(
        jobs.iter()
            .all(|job| matches!(job.lane(), DecryptWorkerLane::Bulk))
    );

    workers
        .dispatch_bulk_fsp_job_batch_or_return(worker_idx, jobs)
        .err()
        .unwrap_or_default()
}

fn drop_returned_fsp_decrypt_jobs(jobs: Vec<FspDecryptJob>) {
    if jobs.is_empty() {
        return;
    }

    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptFspPathFallback,
        jobs.len() as u64,
    );
    drop_fsp_owner_handoff_jobs(jobs);
}

type FspAeadOpenDispatchBatcher = WorkerOpenDispatchBatcher<FspAeadOpenDispatch>;

fn new_fsp_aead_open_dispatch_batcher() -> FspAeadOpenDispatchBatcher {
    WorkerOpenDispatchBatcher::new(DECRYPT_WORKER_BULK_BATCH_MAX)
}

fn dispatch_fsp_aead_open_batch(
    workers: &DecryptWorkerPool,
    key: WorkerOpenDispatchKey,
    jobs: Vec<FspAeadOpenDispatch>,
) -> Vec<FspAeadOpenDispatch> {
    workers
        .dispatch_fsp_aead_open_worker_job_batch_or_return(
            key.worker_idx(),
            key.owner_idx(),
            jobs,
        )
        .err()
        .unwrap_or_default()
}

fn push_fsp_aead_open_dispatch(
    batcher: &mut FspAeadOpenDispatchBatcher,
    workers: &DecryptWorkerPool,
    open_idx: usize,
    owner_idx: usize,
    job: FspAeadOpenDispatch,
) -> Vec<FspAeadOpenDispatch> {
    let key = WorkerOpenDispatchKey::new(open_idx, owner_idx);
    let batch_max = workers.fsp_open_batch_packet_max_for(open_idx);
    batcher.push(key, batch_max, job, |key, jobs| {
        dispatch_fsp_aead_open_batch(workers, key, jobs)
    })
}

fn push_fsp_aead_open_dispatch_batch(
    batcher: &mut FspAeadOpenDispatchBatcher,
    workers: &DecryptWorkerPool,
    open_idx: usize,
    owner_idx: usize,
    jobs: Vec<FspAeadOpenDispatch>,
) -> Vec<FspAeadOpenDispatch> {
    let key = WorkerOpenDispatchKey::new(open_idx, owner_idx);
    let batch_max = workers.fsp_open_batch_packet_max_for(open_idx);
    batcher.push_batch(key, batch_max, jobs, |key, jobs| {
        dispatch_fsp_aead_open_batch(workers, key, jobs)
    })
}

fn flush_fsp_aead_open_dispatch(
    batcher: &mut FspAeadOpenDispatchBatcher,
    workers: &DecryptWorkerPool,
) -> Vec<FspAeadOpenDispatch> {
    batcher.flush(|key, jobs| dispatch_fsp_aead_open_batch(workers, key, jobs))
}
