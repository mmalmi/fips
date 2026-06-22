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

fn try_reserve_bulk_packets_with_previous(
    counter: &AtomicUsize,
    capacity: usize,
    count: usize,
) -> Option<usize> {
    if count == 0 {
        return Some(counter.load(Ordering::Relaxed));
    }

    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(count).filter(|next| *next <= capacity)
        })
        .ok()
}

fn try_reserve_bulk_packets(counter: &AtomicUsize, capacity: usize, count: usize) -> bool {
    try_reserve_bulk_packets_with_previous(counter, capacity, count).is_some()
}

fn try_reserve_bulk_packets_partial(
    counter: &AtomicUsize,
    capacity: usize,
    count: usize,
) -> usize {
    if count == 0 {
        return 0;
    }

    let mut reserved = 0;
    let result = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        let available = capacity.saturating_sub(current);
        if available == 0 {
            reserved = 0;
            return None;
        }
        reserved = count.min(available);
        current
            .checked_add(reserved)
            .filter(|next| *next <= capacity)
    });

    if result.is_ok() { reserved } else { 0 }
}

fn release_bulk_packets(counter: &AtomicUsize, count: usize) {
    if count == 0 {
        return;
    }

    let previous = counter.fetch_sub(count, Ordering::Relaxed);
    debug_assert!(
        previous >= count,
        "decrypt worker bulk job accounting underflow: previous={previous}, release={count}"
    );
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
    fmp_aead_completion_rx: Receiver<FmpAeadCompletionBatch>,
    fsp_aead_completion_rx: Receiver<FspAeadCompletionBatch>,
    bulk_rx: Receiver<DecryptWorkerBulkItem>,
    bulk_queued_packets: Arc<AtomicUsize>,
) {
    trace!(worker = idx, "FMP+FSP decrypt worker thread starting");

    let mut shard = DecryptWorkerShard::new(pool);
    let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();

    loop {
        if drain_worker_queues(
            idx,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fmp_aead_completion_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
            &mut plaintext_batch,
        ) {
            continue;
        }
        match recv_worker_item_biased(
            &control_rx,
            &priority_rx,
            &fmp_aead_completion_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
        ) {
            DecryptWorkerQueueItem::Control(msg) => {
                crate::perf_profile::record_decrypt_worker_select_control();
                let mut batch_stats = DecryptWorkerBatchStats::default();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
                batch_stats.record(idx);
            }
            DecryptWorkerQueueItem::Priority(msg) => {
                crate::perf_profile::record_decrypt_worker_select_priority();
                let mut batch_stats = DecryptWorkerBatchStats::default();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
                batch_stats.record(idx);
            }
            DecryptWorkerQueueItem::FmpAeadCompletion(completions) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerSelectFmpCompletion,
                );
                shard.handle_fmp_aead_completion_batch_msg(idx, completions, &mut plaintext_batch);
                plaintext_batch.flush();
            }
            DecryptWorkerQueueItem::FspAeadCompletion(completions) => {
                crate::perf_profile::record_decrypt_worker_select_fsp_completion(
                    completions.len(),
                );
                shard.handle_fsp_aead_completion_batch_msg(idx, completions, &mut plaintext_batch);
                plaintext_batch.flush();
            }
            DecryptWorkerQueueItem::Bulk(item) => {
                crate::perf_profile::record_decrypt_worker_select_bulk(item.packet_count());
                release_bulk_packets(&bulk_queued_packets, item.packet_count());
                let mut batch_stats = DecryptWorkerBatchStats::default();
                batch_stats.add_bulk_item(&item);
                handle_bulk_item(
                    idx,
                    &mut shard,
                    &control_rx,
                    &priority_rx,
                    &fmp_aead_completion_rx,
                    &fsp_aead_completion_rx,
                    item,
                    &mut plaintext_batch,
                    &mut batch_stats,
                );
                plaintext_batch.flush();
                batch_stats.record(idx);
            }
            DecryptWorkerQueueItem::Closed => {
                drain_worker_queues(
                    idx,
                    &mut shard,
                    &control_rx,
                    &priority_rx,
                    &fmp_aead_completion_rx,
                    &fsp_aead_completion_rx,
                    &bulk_rx,
                    &bulk_queued_packets,
                    &mut plaintext_batch,
                );
                break;
            }
        }
    }
    trace!(worker = idx, "FMP+FSP decrypt worker thread exiting");
}

#[allow(clippy::large_enum_variant)]
enum DecryptWorkerQueueItem {
    Control(WorkerMsg),
    Priority(WorkerMsg),
    FmpAeadCompletion(FmpAeadCompletionBatch),
    FspAeadCompletion(FspAeadCompletionBatch),
    Bulk(DecryptWorkerBulkItem),
    Closed,
}

fn try_recv_fmp_aead_completion(
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletionBatch>,
) -> Option<FmpAeadCompletionBatch> {
    fmp_aead_completion_rx.try_recv().ok()
}

fn try_recv_fsp_aead_completion(
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
) -> Option<FspAeadCompletionBatch> {
    fsp_aead_completion_rx.try_recv().ok()
}

fn handle_fmp_aead_completion(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    completions: FmpAeadCompletionBatch,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
) -> usize {
    let count = completions.len();
    shard.handle_fmp_aead_completion_batch_msg(idx, completions, plaintext_batch);
    count
}

fn handle_fsp_aead_completion(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    completions: FspAeadCompletionBatch,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
) -> usize {
    let count = completions.len();
    shard.handle_fsp_aead_completion_batch_msg(idx, completions, plaintext_batch);
    count
}

fn drain_aead_completions_for_bulk_item(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletionBatch>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    remaining_budget: &mut usize,
) -> bool {
    let started_with_budget = *remaining_budget;
    let mut drained_packets = 0usize;
    let mut drained_messages = 0usize;
    while *remaining_budget > 0 {
        let handled = if let Some(completion) =
            try_recv_fmp_aead_completion(fmp_aead_completion_rx)
        {
            handle_fmp_aead_completion(idx, shard, completion, plaintext_batch)
        } else if let Some(completion) = try_recv_fsp_aead_completion(fsp_aead_completion_rx) {
            handle_fsp_aead_completion(idx, shard, completion, plaintext_batch)
        } else {
            break;
        };
        drained_packets = drained_packets.saturating_add(handled.max(1));
        drained_messages = drained_messages.saturating_add(1);
        *remaining_budget = remaining_budget.saturating_sub(handled.max(1));
    }
    crate::perf_profile::record_decrypt_worker_bulk_interleave_aead_completion(
        drained_messages,
        drained_packets,
    );
    if started_with_budget > 0
        && *remaining_budget == 0
        && (!fmp_aead_completion_rx.is_empty() || !fsp_aead_completion_rx.is_empty())
    {
        crate::perf_profile::record_decrypt_worker_bulk_interleave_budget_exhausted();
    }
    drained_packets > 0
}

fn recv_worker_item_biased(
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletionBatch>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    bulk_rx: &Receiver<DecryptWorkerBulkItem>,
) -> DecryptWorkerQueueItem {
    if let Ok(msg) = control_rx.try_recv() {
        return DecryptWorkerQueueItem::Control(msg);
    }
    if let Ok(msg) = priority_rx.try_recv() {
        return DecryptWorkerQueueItem::Priority(msg);
    }
    if let Some(completion) = try_recv_fmp_aead_completion(fmp_aead_completion_rx) {
        return DecryptWorkerQueueItem::FmpAeadCompletion(completion);
    }
    if let Some(completion) = try_recv_fsp_aead_completion(fsp_aead_completion_rx) {
        return DecryptWorkerQueueItem::FspAeadCompletion(completion);
    }
    crossbeam_channel::select_biased! {
        recv(control_rx) -> msg => match msg {
            Ok(msg) => DecryptWorkerQueueItem::Control(msg),
            Err(_) => DecryptWorkerQueueItem::Closed,
        },
        recv(priority_rx) -> msg => match msg {
            Ok(msg) => DecryptWorkerQueueItem::Priority(msg),
            Err(_) => DecryptWorkerQueueItem::Closed,
        },
        recv(fmp_aead_completion_rx) -> completion => match completion {
            Ok(completion) => DecryptWorkerQueueItem::FmpAeadCompletion(completion),
            Err(_) => DecryptWorkerQueueItem::Closed,
        },
        recv(fsp_aead_completion_rx) -> completion => match completion {
            Ok(completion) => DecryptWorkerQueueItem::FspAeadCompletion(completion),
            Err(_) => DecryptWorkerQueueItem::Closed,
        },
        recv(bulk_rx) -> item => match item {
            Ok(item) => DecryptWorkerQueueItem::Bulk(item),
            Err(_) => DecryptWorkerQueueItem::Closed,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_worker_queues(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletionBatch>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    bulk_rx: &Receiver<DecryptWorkerBulkItem>,
    bulk_queued_packets: &AtomicUsize,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
) -> bool {
    let mut did_work = false;
    let mut batch_stats = DecryptWorkerBatchStats::default();
    while let Ok(msg) = control_rx.try_recv() {
        did_work = true;
        crate::perf_profile::record_decrypt_worker_drain_control();
        batch_stats.add_msg(&msg);
        shard.handle_msg(idx, msg);
    }
    while let Ok(msg) = priority_rx.try_recv() {
        did_work = true;
        crate::perf_profile::record_decrypt_worker_drain_priority();
        batch_stats.add_msg(&msg);
        shard.handle_msg(idx, msg);
    }
    let mut drained_completion_packets = 0usize;
    let mut completion_outputs_need_flush = false;
    let mut drained_bulk_jobs = 0;
    while drained_bulk_jobs < DECRYPT_WORKER_BULK_BURST_BUDGET {
        if let Ok(msg) = control_rx.try_recv() {
            did_work = true;
            plaintext_batch.flush();
            crate::perf_profile::record_decrypt_worker_drain_control();
            batch_stats.add_msg(&msg);
            shard.handle_msg(idx, msg);
            continue;
        }
        if let Ok(msg) = priority_rx.try_recv() {
            did_work = true;
            plaintext_batch.flush();
            crate::perf_profile::record_decrypt_worker_drain_priority();
            batch_stats.add_msg(&msg);
            shard.handle_msg(idx, msg);
            continue;
        }
        if drained_completion_packets < DECRYPT_WORKER_AEAD_COMPLETION_DRAIN_BUDGET {
            let handled = if let Some(completion) =
                try_recv_fmp_aead_completion(fmp_aead_completion_rx)
            {
                handle_fmp_aead_completion(idx, shard, completion, plaintext_batch)
            } else if let Some(completion) = try_recv_fsp_aead_completion(fsp_aead_completion_rx) {
                handle_fsp_aead_completion(idx, shard, completion, plaintext_batch)
            } else {
                0
            };
            if handled > 0 {
                did_work = true;
                drained_completion_packets =
                    drained_completion_packets.saturating_add(handled.max(1));
                completion_outputs_need_flush = true;
                crate::perf_profile::record_decrypt_worker_drain_aead_completion(1, handled);
                continue;
            }
        }
        if completion_outputs_need_flush {
            plaintext_batch.flush();
            completion_outputs_need_flush = false;
        }
        match bulk_rx.try_recv() {
            Ok(item) => {
                did_work = true;
                crate::perf_profile::record_decrypt_worker_drain_bulk(item.packet_count());
                release_bulk_packets(bulk_queued_packets, item.packet_count());
                batch_stats.add_bulk_item(&item);
                drained_bulk_jobs += handle_bulk_item(
                    idx,
                    shard,
                    control_rx,
                    priority_rx,
                    fmp_aead_completion_rx,
                    fsp_aead_completion_rx,
                    item,
                    plaintext_batch,
                    &mut batch_stats,
                );
            }
            Err(_) => break,
        }
    }
    plaintext_batch.flush();
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
    debug_assert!(
        !flush.local_completion,
        "opener worker completions always return to an owner shard"
    );
    if let Some(owner_idx) = flush.owner_idx {
        send_fsp_aead_open_completion_batch(idx, pool, owner_idx, flush.batch);
    }
}

fn send_fmp_aead_open_completion_batch(
    idx: usize,
    pool: &DecryptWorkerPool,
    owner_idx: usize,
    batch: FmpAeadCompletionBatch,
) -> bool {
    if pool.send_fmp_aead_completion_batch(owner_idx, batch) {
        return true;
    }
    debug!(
        worker = idx,
        owner = owner_idx,
        "FMP AEAD opener completion owner gone; dropping completion"
    );
    false
}

fn complete_fmp_aead_open_job(idx: usize, pool: &DecryptWorkerPool, mut job: FmpAeadOpenJob) {
    let Some(owner_idx) = job.completion_owner_idx.take() else {
        return;
    };
    send_fmp_aead_open_completion_batch(
        idx,
        pool,
        owner_idx,
        FmpAeadCompletionBatch::one(job.into_completion()),
    );
}

#[cfg(test)]
fn complete_fsp_aead_open_job(idx: usize, pool: &DecryptWorkerPool, job: FspAeadOpenJob) {
    let mut scratch = FspAeadOpenScratch::default();
    complete_fsp_aead_open_job_with_scratch(idx, pool, job, &mut scratch);
}

fn complete_fsp_aead_open_job_with_scratch(
    idx: usize,
    pool: &DecryptWorkerPool,
    mut job: FspAeadOpenJob,
    scratch: &mut FspAeadOpenScratch,
) {
    let Some(owner_idx) = job.completion_owner_idx.take() else {
        return;
    };
    send_fsp_aead_open_completion_batch(
        idx,
        pool,
        owner_idx,
        FspAeadCompletionBatch::one(job.into_completion_with_scratch(scratch)),
    );
}

fn complete_fsp_aead_open_jobs_with_scratch(
    idx: usize,
    pool: &DecryptWorkerPool,
    jobs: Vec<FspAeadOpenJob>,
    scratch: &mut FspAeadOpenScratch,
) {
    let mut batcher = FspAeadCompletionBatchBuilder::new();

    for mut job in jobs {
        let Some(owner_idx) = job.completion_owner_idx.take() else {
            continue;
        };
        if let Some(flush) = batcher.push(
            false,
            Some(owner_idx),
            job.into_completion_with_scratch(scratch),
        ) {
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
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    fsp_open_batcher: &mut FspAeadOpenJobBatcher,
) {
    let returned = fsp_open_batcher.flush(&shard.pool);
    if !returned.is_empty() {
        shard.drop_returned_fsp_aead_open_jobs(idx, returned, plaintext_batch);
    }
}

struct BulkTurnBatchers<'a> {
    fsp_batcher: Option<&'a mut FspDecryptJobBatcher>,
    fsp_open_batcher: Option<&'a mut FspAeadOpenJobBatcher>,
}

impl<'a> BulkTurnBatchers<'a> {
    fn new(
        fsp_batcher: Option<&'a mut FspDecryptJobBatcher>,
        fsp_open_batcher: Option<&'a mut FspAeadOpenJobBatcher>,
    ) -> Self {
        Self {
            fsp_batcher,
            fsp_open_batcher,
        }
    }

    fn flush_pending(
        &mut self,
        idx: usize,
        shard: &mut DecryptWorkerShard,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        if let Some(fsp_batcher) = self.fsp_batcher.as_deref_mut() {
            fsp_batcher.flush(&shard.pool);
        }
        if let Some(fsp_open_batcher) = self.fsp_open_batcher.as_deref_mut() {
            flush_fsp_open_batcher(idx, shard, plaintext_batch, fsp_open_batcher);
        }
        plaintext_batch.flush();
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_reserved_work_before_bulk_packet(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletionBatch>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    batch_stats: &mut DecryptWorkerBatchStats,
    mut batchers: BulkTurnBatchers<'_>,
) {
    while let Ok(msg) = control_rx.try_recv() {
        batchers.flush_pending(idx, shard, plaintext_batch);
        crate::perf_profile::record_decrypt_worker_drain_control();
        batch_stats.add_msg(&msg);
        shard.handle_msg(idx, msg);
    }
    while let Ok(msg) = priority_rx.try_recv() {
        batchers.flush_pending(idx, shard, plaintext_batch);
        crate::perf_profile::record_decrypt_worker_drain_priority();
        batch_stats.add_msg(&msg);
        shard.handle_msg(idx, msg);
    }
    let mut completion_interleave_budget = DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET;
    if drain_aead_completions_for_bulk_item(
        idx,
        shard,
        fmp_aead_completion_rx,
        fsp_aead_completion_rx,
        plaintext_batch,
        &mut completion_interleave_budget,
    ) {
        plaintext_batch.flush();
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_bulk_item(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    control_rx: &Receiver<WorkerMsg>,
    priority_rx: &Receiver<WorkerMsg>,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletionBatch>,
    fsp_aead_completion_rx: &Receiver<FspAeadCompletionBatch>,
    item: DecryptWorkerBulkItem,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    batch_stats: &mut DecryptWorkerBatchStats,
) -> usize {
    match item {
        DecryptWorkerBulkItem::Job(job) => {
            let item_service_started_at = crate::perf_profile::stamp();
            let item_started_at = crate::perf_profile::stamp();
            record_decrypt_worker_bulk_input_head_wait(job.trace_enqueued_at, 1);
            record_decrypt_worker_bulk_input_tail_wait(item_started_at);
            shard.handle_bulk_job_msg(idx, job, plaintext_batch);
            record_decrypt_worker_bulk_item_service(item_service_started_at, 1);
            1
        }
        DecryptWorkerBulkItem::FspJob(job) => {
            let item_started_at = crate::perf_profile::stamp();
            record_fsp_worker_bulk_input_head_wait(&job);
            record_fsp_worker_bulk_input_tail_wait(item_started_at);
            shard.handle_bulk_fsp_job_msg(idx, job, plaintext_batch);
            1
        }
        DecryptWorkerBulkItem::FmpAeadOpen(job) => {
            let item_service_started_at = crate::perf_profile::stamp();
            complete_fmp_aead_open_job(idx, &shard.pool, job);
            record_decrypt_worker_bulk_item_service(item_service_started_at, 1);
            1
        }
        DecryptWorkerBulkItem::FspAeadOpen(job) => {
            let item_service_started_at = crate::perf_profile::stamp();
            complete_fsp_aead_open_job_with_scratch(
                idx,
                &shard.pool,
                job,
                &mut shard.fsp_open_scratch,
            );
            record_decrypt_worker_bulk_item_service(item_service_started_at, 1);
            1
        }
        DecryptWorkerBulkItem::FspAeadOpenBatch(jobs) => {
            let item_service_started_at = crate::perf_profile::stamp();
            let count = jobs.len();
            complete_fsp_aead_open_jobs_with_scratch(
                idx,
                &shard.pool,
                jobs,
                &mut shard.fsp_open_scratch,
            );
            record_decrypt_worker_bulk_item_service(item_service_started_at, count);
            count
        }
        DecryptWorkerBulkItem::Batch(jobs) => {
            let item_service_started_at = crate::perf_profile::stamp();
            let count = jobs.len();
            let item_started_at = crate::perf_profile::stamp();
            if let Some(job) = jobs.first() {
                record_decrypt_worker_bulk_input_head_wait(job.trace_enqueued_at, count);
            }
            let mut fsp_batcher = FspDecryptJobBatcher::new();
            let mut fsp_open_batcher = FspAeadOpenJobBatcher::new();
            for job in jobs {
                drain_reserved_work_before_bulk_packet(
                    idx,
                    shard,
                    control_rx,
                    priority_rx,
                    fmp_aead_completion_rx,
                    fsp_aead_completion_rx,
                    plaintext_batch,
                    batch_stats,
                    BulkTurnBatchers::new(Some(&mut fsp_batcher), Some(&mut fsp_open_batcher)),
                );
                record_decrypt_worker_bulk_input_tail_wait(item_started_at);
                match shard.handle_job_action(idx, job) {
                    Ok(actions) => {
                        shard.push_job_action_output(
                            idx,
                            actions,
                            plaintext_batch,
                            Some(&mut fsp_batcher),
                            Some(&mut fsp_open_batcher),
                        );
                    }
                    Err(err) => {
                        debug!(worker = idx, error = %err, "decrypt worker job failed");
                    }
                }
            }
            fsp_batcher.flush(&shard.pool);
            flush_fsp_open_batcher(idx, shard, plaintext_batch, &mut fsp_open_batcher);
            record_decrypt_worker_bulk_item_service(item_service_started_at, count);
            count
        }
        DecryptWorkerBulkItem::FspBatch(jobs) => {
            let item_service_started_at = crate::perf_profile::stamp();
            let item_started_at = crate::perf_profile::stamp();
            record_fsp_worker_bulk_input_head_wait_batch(&jobs);
            let count = jobs.len();
            let mut fsp_open_batcher = FspAeadOpenJobBatcher::new();
            for job in jobs {
                drain_reserved_work_before_bulk_packet(
                    idx,
                    shard,
                    control_rx,
                    priority_rx,
                    fmp_aead_completion_rx,
                    fsp_aead_completion_rx,
                    plaintext_batch,
                    batch_stats,
                    BulkTurnBatchers::new(None, Some(&mut fsp_open_batcher)),
                );
                record_fsp_worker_bulk_input_tail_wait(item_started_at);
                shard.handle_bulk_fsp_job_with_open_batcher(
                    idx,
                    job,
                    plaintext_batch,
                    &mut fsp_open_batcher,
                );
            }
            flush_fsp_open_batcher(idx, shard, plaintext_batch, &mut fsp_open_batcher);
            record_decrypt_worker_bulk_item_service(item_service_started_at, count);
            count
        }
    }
}

struct DecryptWorkerOutput {
    fallback_tx: DecryptWorkerFallbackSender,
    event: DecryptWorkerEvent,
    direct_delivery: Option<PendingDirectSessionDelivery>,
}

#[allow(clippy::large_enum_variant)]
enum DecryptWorkerJobAction {
    Output(DecryptWorkerOutput),
    FspJob(FspDecryptJob),
}

impl DecryptWorkerOutput {
    fn send(mut self) -> bool {
        let direct_delivery = self.direct_delivery.take();
        if !self.fallback_tx.send(self.event) {
            return false;
        }
        if let Some(delivery) = direct_delivery {
            delivery.deliver();
        }
        true
    }

    fn is_batchable_bulk_plaintext(&self) -> bool {
        matches!(
            &self.event,
            DecryptWorkerEvent::Plaintext(fallback)
                if matches!(fallback.lane(), DecryptWorkerLane::Bulk)
        )
    }

    fn is_batchable_authenticated_session(&self) -> bool {
        matches!(
            (&self.event, &self.direct_delivery),
            (DecryptWorkerEvent::AuthenticatedSession(session), None)
                if matches!(session.lane, DecryptWorkerLane::Bulk)
        )
    }

    fn is_batchable_direct_endpoint(&self) -> bool {
        matches!(
            (&self.event, &self.direct_delivery),
            (
                DecryptWorkerEvent::DirectSessionCommit(commit),
                Some(delivery),
            ) if matches!(commit.lane, DecryptWorkerLane::Bulk) && delivery.is_endpoint_data()
        )
    }

    fn is_batchable_direct_ipv6(&self) -> bool {
        matches!(
            (&self.event, &self.direct_delivery),
            (
                DecryptWorkerEvent::DirectSessionCommit(commit),
                Some(delivery),
            ) if matches!(commit.lane, DecryptWorkerLane::Bulk) && delivery.is_ipv6_packet()
        )
    }

    fn is_batchable_direct_data(&self) -> bool {
        matches!(
            (&self.event, &self.direct_delivery),
            (DecryptWorkerEvent::DirectSessionData(direct), None)
                if matches!(direct.lane, DecryptWorkerLane::Bulk)
        )
    }
}
