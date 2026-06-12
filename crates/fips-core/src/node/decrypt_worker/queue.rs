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
    FspJob(FspDecryptJob),
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
    Job(DecryptJob),
    FspJob(FspDecryptJob),
    Batch(Vec<DecryptJob>),
    FspBatch(Vec<FspDecryptJob>),
}

impl DecryptWorkerBulkItem {
    fn packet_count(&self) -> usize {
        match self {
            Self::Job(_) | Self::FspJob(_) => 1,
            Self::Batch(jobs) => jobs.len(),
            Self::FspBatch(jobs) => jobs.len(),
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
            WorkerMsg::FspJob(job) => self.add_lane(job.lane(), 1),
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
            DecryptWorkerBulkItem::Job(job) => self.add_lane(job.lane(), 1),
            DecryptWorkerBulkItem::FspJob(job) => self.add_lane(job.lane(), 1),
            DecryptWorkerBulkItem::Batch(jobs) => {
                self.add_lane(DecryptWorkerLane::Bulk, jobs.len());
            }
            DecryptWorkerBulkItem::FspBatch(jobs) => {
                self.add_lane(DecryptWorkerLane::Bulk, jobs.len());
            }
        }
    }

    fn record(&self) {
        if !self.enabled {
            return;
        }
        crate::perf_profile::record_decrypt_worker_batch(
            self.packets,
            self.priority_packets,
            self.bulk_packets,
            DECRYPT_WORKER_BULK_BURST_BUDGET,
        );
    }
}

struct FspDecryptJob {
    fallback_tx: DecryptWorkerFallbackSender,
    fallback: DecryptFallback,
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
        self.fallback.lane()
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

pub(crate) struct DecryptJobBatcher {
    worker_idx: Option<usize>,
    jobs: Vec<DecryptJob>,
}

impl DecryptJobBatcher {
    pub(crate) fn new() -> Self {
        Self {
            worker_idx: None,
            jobs: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
        }
    }

    #[cfg(test)]
    fn pending_buffer_ptr(&self) -> *const DecryptJob {
        self.jobs.as_ptr()
    }

    pub(crate) fn push(&mut self, workers: &DecryptWorkerPool, job: DecryptJob) {
        if !job.is_bulk_lane() {
            self.flush(workers);
            workers.dispatch_job(job);
            return;
        }

        let worker_idx = workers.worker_idx_for(job.session_key);
        let batch_max = workers.bulk_batch_packet_max_for(worker_idx);
        if self.worker_idx != Some(worker_idx) || self.jobs.len() >= batch_max {
            self.flush(workers);
        }
        self.worker_idx = Some(worker_idx);
        self.jobs.push(job);

        if self.jobs.len() >= batch_max {
            self.flush(workers);
        }
    }

    pub(crate) fn flush(&mut self, workers: &DecryptWorkerPool) {
        let Some(worker_idx) = self.worker_idx.take() else {
            return;
        };
        if self.jobs.is_empty() {
            return;
        }

        if self.jobs.len() == 1 {
            let job = self.jobs.pop().expect("checked single pending job");
            workers.dispatch_bulk_job(worker_idx, job);
            return;
        }

        let jobs = std::mem::replace(
            &mut self.jobs,
            Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
        );
        workers.dispatch_bulk_job_batch(worker_idx, jobs);
    }
}

struct FspDecryptJobBatcher {
    worker_idx: Option<usize>,
    jobs: Vec<FspDecryptJob>,
}

impl FspDecryptJobBatcher {
    fn new() -> Self {
        Self {
            worker_idx: None,
            jobs: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
        }
    }

    fn push(
        &mut self,
        workers: &DecryptWorkerPool,
        job: FspDecryptJob,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        if !matches!(job.lane(), DecryptWorkerLane::Bulk) {
            self.flush(workers, plaintext_batch);
            if let Err(job) = workers.dispatch_fsp_job_or_return(job) {
                plaintext_batch.push_fsp_job_fallback(job);
            }
            return;
        }

        let worker_idx = workers.worker_idx_for_fsp(&job.source_addr);
        let batch_max = workers.bulk_batch_packet_max_for(worker_idx);
        if self.worker_idx != Some(worker_idx) || self.jobs.len() >= batch_max {
            self.flush(workers, plaintext_batch);
        }
        self.worker_idx = Some(worker_idx);
        self.jobs.push(job);

        if self.jobs.len() >= batch_max {
            self.flush(workers, plaintext_batch);
        }
    }

    fn flush(
        &mut self,
        workers: &DecryptWorkerPool,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        let Some(worker_idx) = self.worker_idx.take() else {
            return;
        };
        if self.jobs.is_empty() {
            return;
        }

        if self.jobs.len() == 1 {
            let job = self.jobs.pop().expect("checked single pending FSP job");
            if let Err(job) = workers.dispatch_bulk_fsp_job_or_return(worker_idx, job) {
                plaintext_batch.push_fsp_job_fallback(job);
            }
            return;
        }

        let jobs = std::mem::replace(
            &mut self.jobs,
            Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
        );
        if let Err(jobs) = workers.dispatch_bulk_fsp_job_batch_or_return(worker_idx, jobs) {
            for job in jobs {
                plaintext_batch.push_fsp_job_fallback(job);
            }
        }
    }
}
