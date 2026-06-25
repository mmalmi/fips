fn record_decrypt_worker_bulk_drop_count(worker: usize, count: usize) {
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptWorkerQueueFull,
        count as u64,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptWorkerBulkDropped,
        count as u64,
    );
    static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = FULL_COUNT.fetch_add(count as u64, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(10000) {
        warn!(
            worker,
            drops = n + count as u64,
            dropped = count,
            "DecryptWorker bulk channel full; dropping inbound packets"
        );
    }
}

fn record_decrypt_worker_priority_drop(worker: usize, kind: &'static str) {
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerQueueFull);
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerPriorityDropped);
    static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = FULL_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(10000) {
        warn!(
            worker,
            kind,
            drops = n + 1,
            "DecryptWorker priority channel full; dropping inbound item"
        );
    }
}

fn record_decrypt_worker_return_drop_count(
    event: crate::perf_profile::Event,
    lane: DecryptWorkerLane,
    count: usize,
) {
    crate::perf_profile::record_event_count(event, count as u64);
    static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = FULL_COUNT.fetch_add(count as u64, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(10000) {
        warn!(
            ?lane,
            drops = n + count as u64,
            dropped = count,
            "DecryptWorker return channel full; dropping worker event"
        );
    }
}

fn run_worker(
    idx: usize,
    pool: DecryptWorkerPool,
    control_rx: Receiver<WorkerMsg>,
    priority_rx: Receiver<WorkerMsg>,
    fsp_aead_completion_rx: Receiver<FspAeadCompletionBatch>,
    bulk_rx: Receiver<DecryptWorkerBulkItem>,
    bulk_credits: LaneCreditGate,
) {
    trace!(worker = idx, "FMP+FSP decrypt worker thread starting");

    let return_tx = pool.return_tx.clone();
    let mut shard = DecryptWorkerShard::new(pool);
    let mut return_batch = DecryptWorkerReturnBatch::new(return_tx);
    let mut bulk_batchers = BulkBatchBuffers::new();

    loop {
        if drain_worker_queues_with_buffers(
            idx,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
            &bulk_credits,
            &mut return_batch,
            &mut bulk_batchers,
        ) {
            continue;
        }
        match recv_biased_worker_queue_item(
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
        ) {
            WorkerQueueItem::Control(msg) => {
                crate::perf_profile::record_decrypt_worker_select_control();
                let mut batch_stats = DecryptWorkerBatchStats::default();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
                batch_stats.record(idx);
            }
            WorkerQueueItem::Priority(msg) => {
                crate::perf_profile::record_decrypt_worker_select_priority();
                let mut batch_stats = DecryptWorkerBatchStats::default();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
                batch_stats.record(idx);
            }
            WorkerQueueItem::Completion(completions) => {
                crate::perf_profile::record_decrypt_worker_select_fsp_completion(
                    completions.len(),
                );
                shard.handle_fsp_aead_completion_batch_msg(idx, completions, &mut return_batch);
                return_batch.flush();
            }
            WorkerQueueItem::Bulk(item) => {
                crate::perf_profile::record_decrypt_worker_select_bulk(item.packet_count());
                bulk_credits.release_count(item.packet_count());
                let mut batch_stats = DecryptWorkerBatchStats::default();
                batch_stats.add_bulk_item(&item);
                handle_bulk_item_with_buffers(
                    idx,
                    &mut shard,
                    &control_rx,
                    &priority_rx,
                    &fsp_aead_completion_rx,
                    item,
                    &mut return_batch,
                    &mut batch_stats,
                    &mut bulk_batchers,
                );
                return_batch.flush();
                batch_stats.record(idx);
            }
            WorkerQueueItem::Closed => {
                drain_worker_queues_with_buffers(
                    idx,
                    &mut shard,
                    &control_rx,
                    &priority_rx,
                    &fsp_aead_completion_rx,
                    &bulk_rx,
                    &bulk_credits,
                    &mut return_batch,
                    &mut bulk_batchers,
                );
                break;
            }
        }
    }
    trace!(worker = idx, "FMP+FSP decrypt worker thread exiting");
}

fn handle_fsp_aead_completion(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    completions: FspAeadCompletionBatch,
    return_batch: &mut DecryptWorkerReturnBatch,
) -> usize {
    let count = completions.len();
    shard.handle_fsp_aead_completion_batch_msg(idx, completions, return_batch);
    count
}

fn drain_aead_completions_for_bulk_item(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    return_batch: &mut DecryptWorkerReturnBatch,
    remaining_budget: &mut usize,
) -> bool {
    let started_with_budget = *remaining_budget;
    let mut drained_packets = 0usize;
    let mut drained_messages = 0usize;
    while *remaining_budget > 0 {
        let Ok(completion) = fsp_aead_completion_rx.try_recv() else {
            break;
        };
        let handled = handle_fsp_aead_completion(idx, shard, completion, return_batch);
        drained_packets = drained_packets.saturating_add(handled.max(1));
        drained_messages = drained_messages.saturating_add(1);
        *remaining_budget = remaining_budget.saturating_sub(handled.max(1));
    }
    crate::perf_profile::record_decrypt_worker_bulk_interleave_aead_completion(
        drained_messages,
        drained_packets,
    );
    if started_with_budget > 0 && *remaining_budget == 0 && !fsp_aead_completion_rx.is_empty() {
        crate::perf_profile::record_decrypt_worker_bulk_interleave_budget_exhausted();
    }
    drained_packets > 0
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn drain_worker_queues(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    bulk_rx: &Receiver<DecryptWorkerBulkItem>,
    bulk_credits: &LaneCreditGate,
    return_batch: &mut DecryptWorkerReturnBatch,
) -> bool {
    let mut bulk_batchers = BulkBatchBuffers::new();
    drain_worker_queues_with_buffers(
        idx,
        shard,
        control_rx,
        priority_rx,
        fsp_aead_completion_rx,
        bulk_rx,
        bulk_credits,
        return_batch,
        &mut bulk_batchers,
    )
}

#[allow(clippy::too_many_arguments)]
fn drain_worker_queues_with_buffers(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    bulk_rx: &Receiver<DecryptWorkerBulkItem>,
    bulk_credits: &LaneCreditGate,
    return_batch: &mut DecryptWorkerReturnBatch,
    bulk_batchers: &mut BulkBatchBuffers,
) -> bool {
    let mut did_work = false;
    let mut batch_stats = DecryptWorkerBatchStats::default();

    while let Some(item) = try_recv_reserved_worker_queue_item(control_rx, priority_rx) {
        did_work = true;
        match item {
            WorkerReservedQueueItem::Control(msg) => {
                crate::perf_profile::record_decrypt_worker_drain_control();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
            }
            WorkerReservedQueueItem::Priority(msg) => {
                crate::perf_profile::record_decrypt_worker_drain_priority();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
            }
        }
    }

    let mut drain_cursor = WorkerDrainCursor::new(
        DECRYPT_WORKER_BULK_BURST_BUDGET,
        DECRYPT_WORKER_AEAD_COMPLETION_DRAIN_BUDGET,
    );
    while let Some(action) = drain_cursor.next(
        control_rx,
        priority_rx,
        fsp_aead_completion_rx,
        bulk_rx,
        |completion: &FspAeadCompletionBatch| completion.len(),
    ) {
        match action {
            WorkerDrainAction::Control {
                item: msg,
                flush_completion_outputs,
            } => {
                did_work = true;
                if flush_completion_outputs {
                    return_batch.flush();
                }
                crate::perf_profile::record_decrypt_worker_drain_control();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
            }
            WorkerDrainAction::Priority {
                item: msg,
                flush_completion_outputs,
            } => {
                did_work = true;
                if flush_completion_outputs {
                    return_batch.flush();
                }
                crate::perf_profile::record_decrypt_worker_drain_priority();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
            }
            WorkerDrainAction::Completion(completion) => {
                did_work = true;
                let completion_packets = completion.len();
                let handled = handle_fsp_aead_completion(idx, shard, completion, return_batch);
                crate::perf_profile::record_decrypt_worker_drain_aead_completion(1, handled);
                debug_assert_eq!(
                    handled, completion_packets,
                    "FSP AEAD completion batch handler should retire every completion"
                );
            }
            WorkerDrainAction::FlushCompletionOutputs => {
                return_batch.flush();
            }
            WorkerDrainAction::Bulk(item) => {
                did_work = true;
                crate::perf_profile::record_decrypt_worker_drain_bulk(item.packet_count());
                bulk_credits.release_count(item.packet_count());
                batch_stats.add_bulk_item(&item);
                let processed = handle_bulk_item_with_buffers(
                    idx,
                    shard,
                    control_rx,
                    priority_rx,
                    fsp_aead_completion_rx,
                    item,
                    return_batch,
                    &mut batch_stats,
                    bulk_batchers,
                );
                drain_cursor.charge_bulk_work(processed);
            }
        }
    }

    return_batch.flush();
    batch_stats.record(idx);
    did_work
}

#[inline]
fn record_fsp_worker_bulk_input_head_wait(job: &FspDecryptJob) {
    crate::perf_profile::record_since_count(
        crate::perf_profile::Stage::DecryptFspWorkerBulkInputHeadWait,
        job.trace_enqueued_at,
        1,
    );
}

#[inline]
fn record_fsp_worker_bulk_input_head_wait_batch(jobs: &[FspDecryptJob]) {
    if !crate::perf_profile::enabled() {
        return;
    }
    for job in jobs {
        record_fsp_worker_bulk_input_head_wait(job);
    }
}

#[inline]
fn record_fsp_worker_bulk_input_tail_wait(
    item_started_at: Option<crate::perf_profile::TraceStamp>,
) {
    crate::perf_profile::record_since_count(
        crate::perf_profile::Stage::DecryptFspWorkerBulkInputTailWait,
        item_started_at,
        1,
    );
}

#[inline]
fn record_decrypt_worker_bulk_input_head_wait(
    queued_at: Option<crate::perf_profile::TraceStamp>,
    count: usize,
) {
    crate::perf_profile::record_decrypt_worker_bulk_input_wait(queued_at, count as u64);
}

#[inline]
fn record_decrypt_worker_bulk_input_tail_wait(
    item_started_at: Option<crate::perf_profile::TraceStamp>,
) {
    crate::perf_profile::record_since_count(
        crate::perf_profile::Stage::DecryptWorkerBulkInputTailWait,
        item_started_at,
        1,
    );
}

#[inline]
fn record_decrypt_worker_bulk_item_service(
    item_started_at: Option<crate::perf_profile::TraceStamp>,
    count: usize,
) {
    crate::perf_profile::record_since_count(
        crate::perf_profile::Stage::DecryptWorkerBulkItemService,
        item_started_at,
        count as u64,
    );
}

fn send_fsp_aead_open_completion_batch(
    idx: usize,
    pool: &DecryptWorkerPool,
    owner_idx: usize,
    batch: FspAeadCompletionBatch,
) -> bool {
    let count = batch.len();
    if pool.send_fsp_aead_completion_batch(owner_idx, batch) {
        return true;
    }
    record_fsp_aead_completion_drop(
        crate::perf_profile::Event::FspAeadCompletionStaleSession,
        count,
    );
    debug!(
        worker = idx,
        owner = owner_idx,
        completions = count,
        "FSP AEAD opener completion owner gone; dropping completion"
    );
    false
}

fn send_fsp_aead_open_completion_flush(
    idx: usize,
    pool: &DecryptWorkerPool,
    flush: FspAeadCompletionBatchFlush,
) {
    send_fsp_aead_open_completion_batch(idx, pool, flush.route, flush.batch);
}

#[cfg(test)]
fn complete_fsp_aead_open_job(idx: usize, pool: &DecryptWorkerPool, job: FspAeadOpenDispatch) {
    complete_fsp_aead_open_jobs(idx, pool, vec![job]);
}

fn complete_fsp_aead_open_jobs(idx: usize, pool: &DecryptWorkerPool, jobs: Vec<FspAeadOpenDispatch>) {
    let mut batcher = new_fsp_aead_completion_batcher();

    for job in jobs {
        let Some(owner_idx) = job.completion_owner_idx() else {
            continue;
        };
        if let Some(flush) = batcher.push(owner_idx, job.into_completion()) {
            send_fsp_aead_open_completion_flush(idx, pool, flush);
        }
    }

    if let Some(flush) = batcher.flush() {
        send_fsp_aead_open_completion_flush(idx, pool, flush);
    }
}

fn flush_fsp_open_batcher(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    return_batch: &mut DecryptWorkerReturnBatch,
    fsp_open_batcher: &mut FspAeadOpenDispatchBatcher,
) {
    let returned = flush_fsp_aead_open_dispatch(fsp_open_batcher, &shard.pool);
    if !returned.is_empty() {
        shard.drop_returned_fsp_aead_open_jobs(idx, returned, return_batch);
    }
}

struct BulkBatchBuffers {
    fsp_batcher: FspDecryptJobBatcher,
    fsp_open_batcher: FspAeadOpenDispatchBatcher,
}

impl BulkBatchBuffers {
    fn new() -> Self {
        Self {
            fsp_batcher: FspDecryptJobBatcher::new(),
            fsp_open_batcher: new_fsp_aead_open_dispatch_batcher(),
        }
    }

    fn is_empty(&self) -> bool {
        self.fsp_batcher.is_empty() && self.fsp_open_batcher.is_empty()
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_reserved_work_before_bulk_item(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    return_batch: &mut DecryptWorkerReturnBatch,
    batch_stats: &mut DecryptWorkerBatchStats,
) {
    while let Some(item) = try_recv_reserved_worker_queue_item(control_rx, priority_rx) {
        match item {
            WorkerReservedQueueItem::Control(msg) => {
                return_batch.flush();
                crate::perf_profile::record_decrypt_worker_drain_control();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
            }
            WorkerReservedQueueItem::Priority(msg) => {
                return_batch.flush();
                crate::perf_profile::record_decrypt_worker_drain_priority();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
            }
        }
    }
    let mut completion_interleave_budget = DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET;
    if drain_aead_completions_for_bulk_item(
        idx,
        shard,
        fsp_aead_completion_rx,
        return_batch,
        &mut completion_interleave_budget,
    ) {
        return_batch.flush();
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn handle_bulk_item(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    item: DecryptWorkerBulkItem,
    return_batch: &mut DecryptWorkerReturnBatch,
    batch_stats: &mut DecryptWorkerBatchStats,
) -> usize {
    let mut bulk_batchers = BulkBatchBuffers::new();
    handle_bulk_item_with_buffers(
        idx,
        shard,
        control_rx,
        priority_rx,
        fsp_aead_completion_rx,
        item,
        return_batch,
        batch_stats,
        &mut bulk_batchers,
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_bulk_item_with_buffers(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    item: DecryptWorkerBulkItem,
    return_batch: &mut DecryptWorkerReturnBatch,
    batch_stats: &mut DecryptWorkerBatchStats,
    bulk_batchers: &mut BulkBatchBuffers,
) -> usize {
    debug_assert!(bulk_batchers.is_empty());
    match item {
        DecryptWorkerBulkItem::FspAeadOpenBatch(jobs) => {
            let item_service_started_at = crate::perf_profile::stamp();
            let count = jobs.len();
            complete_fsp_aead_open_jobs(idx, &shard.pool, jobs);
            record_decrypt_worker_bulk_item_service(item_service_started_at, count);
            count
        }
        DecryptWorkerBulkItem::Batch { session_key, jobs } => {
            let item_service_started_at = crate::perf_profile::stamp();
            let count = jobs.len();
            let item_started_at = crate::perf_profile::stamp();
            let trace_enabled = crate::perf_profile::enabled();
            if let Some(job) = jobs.first() {
                record_decrypt_worker_bulk_input_head_wait(job.trace_enqueued_at, count);
            }
            if count > 1 {
                drain_reserved_work_before_bulk_item(
                    idx,
                    shard,
                    control_rx,
                    priority_rx,
                    fsp_aead_completion_rx,
                    return_batch,
                    batch_stats,
                );
            }
            let fsp_batcher = &mut bulk_batchers.fsp_batcher;
            let fsp_open_batcher = &mut bulk_batchers.fsp_open_batcher;
            if trace_enabled {
                for _ in 0..count {
                    record_decrypt_worker_bulk_input_tail_wait(item_started_at);
                }
            }
            shard.push_bulk_job_outputs(
                idx,
                session_key,
                jobs,
                return_batch,
                fsp_batcher,
                fsp_open_batcher,
            );
            fsp_batcher.flush(&shard.pool);
            flush_fsp_open_batcher(idx, shard, return_batch, &mut *fsp_open_batcher);
            debug_assert!(bulk_batchers.is_empty());
            record_decrypt_worker_bulk_item_service(item_service_started_at, count);
            count
        }
        DecryptWorkerBulkItem::FspBatch(jobs) => {
            let item_service_started_at = crate::perf_profile::stamp();
            let item_started_at = crate::perf_profile::stamp();
            record_fsp_worker_bulk_input_head_wait_batch(&jobs);
            let count = jobs.len();
            let trace_enabled = crate::perf_profile::enabled();
            drain_reserved_work_before_bulk_item(
                idx,
                shard,
                control_rx,
                priority_rx,
                fsp_aead_completion_rx,
                return_batch,
                batch_stats,
            );
            let fsp_open_batcher = &mut bulk_batchers.fsp_open_batcher;
            shard.handle_bulk_fsp_job_batch_with_open_batcher(
                idx,
                jobs,
                item_started_at,
                trace_enabled,
                return_batch,
                &mut *fsp_open_batcher,
            );
            flush_fsp_open_batcher(idx, shard, return_batch, &mut *fsp_open_batcher);
            debug_assert!(bulk_batchers.is_empty());
            record_decrypt_worker_bulk_item_service(item_service_started_at, count);
            count
        }
    }
}

struct DecryptWorkerOutput {
    event: DecryptWorkerEvent,
    direct_delivery: Option<PendingDirectSessionDelivery>,
}

#[allow(clippy::large_enum_variant)]
enum DecryptWorkerJobAction {
    Output(DecryptWorkerOutput),
    FspJob(FspDecryptJob),
}

impl DecryptWorkerOutput {
    fn send(mut self, return_tx: &DecryptWorkerReturnSender) -> bool {
        let direct_delivery = self.direct_delivery.take();
        if !return_tx.send(self.event) {
            return false;
        }
        if let Some(delivery) = direct_delivery {
            delivery.deliver();
        }
        true
    }
}
