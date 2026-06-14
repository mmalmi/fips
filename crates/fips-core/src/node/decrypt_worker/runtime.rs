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
    priority_rx: Receiver<WorkerMsg>,
    fmp_aead_completion_rx: Receiver<FmpAeadCompletion>,
    bulk_rx: Receiver<DecryptWorkerBulkItem>,
    bulk_queued_packets: Arc<AtomicUsize>,
) {
    trace!(worker = idx, "FMP+FSP decrypt worker thread starting");

    let mut shard = DecryptWorkerShard::new(pool);

    loop {
        drain_worker_queues(
            idx,
            &mut shard,
            &priority_rx,
            &fmp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
        );
        match recv_worker_item_biased(&priority_rx, &fmp_aead_completion_rx, &bulk_rx) {
            DecryptWorkerQueueItem::Priority(msg) => {
                let mut batch_stats = DecryptWorkerBatchStats::default();
                batch_stats.add_msg(&msg);
                shard.handle_msg(idx, msg);
                batch_stats.record();
            }
            DecryptWorkerQueueItem::FmpAeadCompletion(completion) => {
                let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
                shard.handle_fmp_aead_completion_msg(idx, completion, &mut plaintext_batch);
                plaintext_batch.flush();
            }
            DecryptWorkerQueueItem::Bulk(item) => {
                release_bulk_packets(&bulk_queued_packets, item.packet_count());
                let mut batch_stats = DecryptWorkerBatchStats::default();
                batch_stats.add_bulk_item(&item);
                let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
                handle_bulk_item(
                    idx,
                    &mut shard,
                    &priority_rx,
                    &fmp_aead_completion_rx,
                    item,
                    &mut plaintext_batch,
                    &mut batch_stats,
                );
                plaintext_batch.flush();
                batch_stats.record();
            }
            DecryptWorkerQueueItem::Closed => {
                drain_worker_queues(
                    idx,
                    &mut shard,
                    &priority_rx,
                    &fmp_aead_completion_rx,
                    &bulk_rx,
                    &bulk_queued_packets,
                );
                break;
            }
        }
    }
    trace!(worker = idx, "FMP+FSP decrypt worker thread exiting");
}

#[allow(clippy::large_enum_variant)]
enum DecryptWorkerQueueItem {
    Priority(WorkerMsg),
    FmpAeadCompletion(FmpAeadCompletion),
    Bulk(DecryptWorkerBulkItem),
    Closed,
}

fn recv_worker_item_biased(
    priority_rx: &Receiver<WorkerMsg>,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletion>,
    bulk_rx: &Receiver<DecryptWorkerBulkItem>,
) -> DecryptWorkerQueueItem {
    crossbeam_channel::select_biased! {
        recv(priority_rx) -> msg => match msg {
            Ok(msg) => DecryptWorkerQueueItem::Priority(msg),
            Err(_) => DecryptWorkerQueueItem::Closed,
        },
        recv(fmp_aead_completion_rx) -> completion => match completion {
            Ok(completion) => DecryptWorkerQueueItem::FmpAeadCompletion(completion),
            Err(_) => DecryptWorkerQueueItem::Closed,
        },
        recv(bulk_rx) -> item => match item {
            Ok(item) => DecryptWorkerQueueItem::Bulk(item),
            Err(_) => DecryptWorkerQueueItem::Closed,
        },
    }
}

fn drain_worker_queues(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    priority_rx: &Receiver<WorkerMsg>,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletion>,
    bulk_rx: &Receiver<DecryptWorkerBulkItem>,
    bulk_queued_packets: &AtomicUsize,
) {
    let mut batch_stats = DecryptWorkerBatchStats::default();
    while let Ok(msg) = priority_rx.try_recv() {
        batch_stats.add_msg(&msg);
        shard.handle_msg(idx, msg);
    }
    let mut drained_bulk_jobs = 0;
    let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
    while drained_bulk_jobs < DECRYPT_WORKER_BULK_BURST_BUDGET {
        if let Ok(msg) = priority_rx.try_recv() {
            plaintext_batch.flush();
            batch_stats.add_msg(&msg);
            shard.handle_msg(idx, msg);
            continue;
        }
        if let Ok(completion) = fmp_aead_completion_rx.try_recv() {
            drained_bulk_jobs += 1;
            shard.handle_fmp_aead_completion_msg(idx, completion, &mut plaintext_batch);
            continue;
        }
        match bulk_rx.try_recv() {
            Ok(item) => {
                release_bulk_packets(bulk_queued_packets, item.packet_count());
                batch_stats.add_bulk_item(&item);
                drained_bulk_jobs += handle_bulk_item(
                    idx,
                    shard,
                    priority_rx,
                    fmp_aead_completion_rx,
                    item,
                    &mut plaintext_batch,
                    &mut batch_stats,
                );
            }
            Err(_) => break,
        }
    }
    plaintext_batch.flush();
    batch_stats.record();
}

fn wait_for_fmp_receive_order_window(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    priority_rx: &Receiver<WorkerMsg>,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletion>,
    session_key: DecryptSessionKey,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    batch_stats: &mut DecryptWorkerBatchStats,
) -> bool {
    if !shard.pool.fmp_aead_helpers_enabled() {
        return true;
    }

    let mut wait_started_at = None;
    while !shard.fmp_receive_order_window_available(session_key) {
        if wait_started_at.is_none() {
            wait_started_at = crate::perf_profile::stamp();
        }
        plaintext_batch.flush();
        crossbeam_channel::select_biased! {
            recv(priority_rx) -> msg => match msg {
                Ok(msg) => {
                    batch_stats.add_msg(&msg);
                    shard.handle_msg(idx, msg);
                }
                Err(_) => {
                    record_fmp_receive_order_window_wait(wait_started_at);
                    return false;
                }
            },
            recv(fmp_aead_completion_rx) -> completion => match completion {
                Ok(completion) => {
                    shard.handle_fmp_aead_completion_msg(idx, completion, plaintext_batch);
                }
                Err(_) => {
                    record_fmp_receive_order_window_wait(wait_started_at);
                    return false;
                }
            },
        }
    }
    record_fmp_receive_order_window_wait(wait_started_at);
    true
}

#[inline]
fn record_fmp_receive_order_window_wait(wait_started_at: Option<crate::perf_profile::TraceStamp>) {
    if wait_started_at.is_some() {
        crate::perf_profile::record_since_count(
            crate::perf_profile::Stage::FmpReceiveOrderWindowWait,
            wait_started_at,
            1,
        );
    }
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
    if item_started_at.is_some() {
        crate::perf_profile::record_since_count(
            crate::perf_profile::Stage::DecryptWorkerBulkInputTailWait,
            item_started_at,
            1,
        );
    }
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

fn handle_bulk_item(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    priority_rx: &Receiver<WorkerMsg>,
    fmp_aead_completion_rx: &Receiver<FmpAeadCompletion>,
    item: DecryptWorkerBulkItem,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    batch_stats: &mut DecryptWorkerBatchStats,
) -> usize {
    let item_service_started_at = crate::perf_profile::stamp();
    let count = match item {
        DecryptWorkerBulkItem::Job(job) => {
            let item_started_at = crate::perf_profile::stamp();
            record_decrypt_worker_bulk_input_head_wait(job.trace_enqueued_at, 1);
            record_decrypt_worker_bulk_input_tail_wait(item_started_at);
            shard.handle_bulk_job_msg(idx, job, plaintext_batch);
            1
        }
        DecryptWorkerBulkItem::FspJob(job) => {
            shard.handle_bulk_fsp_job_msg(idx, job, plaintext_batch);
            1
        }
        DecryptWorkerBulkItem::Batch(jobs) => {
            let count = jobs.len();
            let item_started_at = crate::perf_profile::stamp();
            if let Some(job) = jobs.first() {
                record_decrypt_worker_bulk_input_head_wait(job.trace_enqueued_at, count);
            }
            let mut fsp_batcher = FspDecryptJobBatcher::new();
            for job in jobs {
                while let Ok(msg) = priority_rx.try_recv() {
                    fsp_batcher.flush(&shard.pool, plaintext_batch);
                    plaintext_batch.flush();
                    batch_stats.add_msg(&msg);
                    shard.handle_msg(idx, msg);
                }
                while let Ok(completion) = fmp_aead_completion_rx.try_recv() {
                    fsp_batcher.flush(&shard.pool, plaintext_batch);
                    shard.handle_fmp_aead_completion_msg(idx, completion, plaintext_batch);
                }
                if !wait_for_fmp_receive_order_window(
                    idx,
                    shard,
                    priority_rx,
                    fmp_aead_completion_rx,
                    job.session_key,
                    plaintext_batch,
                    batch_stats,
                ) {
                    break;
                }
                record_decrypt_worker_bulk_input_tail_wait(item_started_at);
                match shard.handle_job_action(idx, job) {
                    Ok(actions) => {
                        shard.push_job_actions_output(
                            idx,
                            actions,
                            plaintext_batch,
                            Some(&mut fsp_batcher),
                        );
                    }
                    Err(err) => {
                        debug!(worker = idx, error = %err, "decrypt worker job failed");
                    }
                }
            }
            fsp_batcher.flush(&shard.pool, plaintext_batch);
            count
        }
        DecryptWorkerBulkItem::FspBatch(jobs) => {
            let count = jobs.len();
            for job in jobs {
                while let Ok(msg) = priority_rx.try_recv() {
                    plaintext_batch.flush();
                    batch_stats.add_msg(&msg);
                    shard.handle_msg(idx, msg);
                }
                while let Ok(completion) = fmp_aead_completion_rx.try_recv() {
                    shard.handle_fmp_aead_completion_msg(idx, completion, plaintext_batch);
                }
                shard.handle_bulk_fsp_job_msg(idx, job, plaintext_batch);
            }
            count
        }
    };
    record_decrypt_worker_bulk_item_service(item_service_started_at, count);
    count
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

#[allow(clippy::large_enum_variant)]
enum DecryptWorkerJobActions {
    None,
    One(DecryptWorkerJobAction),
    Many(Vec<DecryptWorkerJobAction>),
}

impl DecryptWorkerJobActions {
    fn one(action: DecryptWorkerJobAction) -> Self {
        Self::One(action)
    }

    fn push(&mut self, action: DecryptWorkerJobAction) {
        match std::mem::replace(self, Self::None) {
            Self::None => {
                *self = Self::One(action);
            }
            Self::One(existing) => {
                *self = Self::Many(vec![existing, action]);
            }
            Self::Many(mut actions) => {
                actions.push(action);
                *self = Self::Many(actions);
            }
        }
    }

    fn for_each(self, mut on_action: impl FnMut(DecryptWorkerJobAction)) {
        match self {
            Self::None => {}
            Self::One(action) => on_action(action),
            Self::Many(actions) => {
                for action in actions {
                    on_action(action);
                }
            }
        }
    }
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

    fn is_batchable_direct_endpoint(&self) -> bool {
        matches!(
            (&self.event, &self.direct_delivery),
            (
                DecryptWorkerEvent::DirectSessionCommit(commit),
                Some(delivery),
            ) if matches!(commit.lane, DecryptWorkerLane::Bulk) && delivery.is_endpoint_data()
        )
    }

    fn is_batchable_direct_fmp_endpoint_data(&self) -> bool {
        matches!(
            (&self.event, &self.direct_delivery),
            (DecryptWorkerEvent::DirectFmpEndpointData(endpoint), None)
                if matches!(endpoint.lane, DecryptWorkerLane::Bulk)
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
}
