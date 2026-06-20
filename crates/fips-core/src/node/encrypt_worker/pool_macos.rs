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
    #[cfg(target_os = "macos")]
    macos_senders: Arc<MacSequencedSendFlows>,
    #[cfg(target_os = "linux")]
    linux_senders: Arc<LinuxSequencedSendFlows>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
        Self {
            senders: senders.into(),
            #[cfg(target_os = "macos")]
            macos_senders: Arc::new(MacSequencedSendFlows::default()),
            #[cfg(target_os = "linux")]
            linux_senders: Arc::new(LinuxSequencedSendFlows::default()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
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
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping job");
            return;
        }
        let (idx, job) = self.prepare_dispatch(job);
        self.dispatch_to_worker(idx, job);
    }

    pub(crate) fn dispatch_bulk_batch(&self, jobs: Vec<FmpSendJob>) {
        #[cfg(target_os = "linux")]
        if linux_ordered_container_sender_enabled() {
            self.dispatch_linux_ordered_bulk_batch(jobs);
            return;
        }

        for job in jobs {
            self.dispatch(job);
        }
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

    #[cfg(target_os = "linux")]
    fn dispatch_linux_ordered_bulk_batch(&self, jobs: Vec<FmpSendJob>) {
        if jobs.len() <= 1 || jobs.iter().any(|job| !job.bulk_endpoint_data) {
            for job in jobs {
                self.dispatch(job);
            }
            return;
        }

        let chunk_size = linux_ordered_container_chunk_size();
        let mut iter = jobs.into_iter().peekable();
        while let Some(first) = iter.next() {
            let dispatch_key = SendDispatchKey::new(
                first.send_target_key(),
                first.endpoint_flow_dispatch_key,
            );
            let mut chunk = Vec::with_capacity(chunk_size);
            chunk.push(first);

            while chunk.len() < chunk_size {
                let Some(next) = iter.peek() else {
                    break;
                };
                let next_key =
                    SendDispatchKey::new(next.send_target_key(), next.endpoint_flow_dispatch_key);
                if next_key != dispatch_key || !next.bulk_endpoint_data {
                    break;
                }
                chunk.push(iter.next().expect("peeked job exists"));
            }

            self.dispatch_linux_ordered_chunk(dispatch_key, chunk);
        }
    }

    #[cfg(target_os = "linux")]
    fn dispatch_linux_ordered_chunk(&self, dispatch_key: SendDispatchKey, jobs: Vec<FmpSendJob>) {
        let Some(first) = jobs.first() else {
            return;
        };
        let flow = self
            .linux_senders
            .flow_for(dispatch_key, first.send_target.clone());
        let chunk_seq = flow.reserve_seq();
        let start_idx = self
            .next_worker
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.senders.len();
        let worker_stride = linux_ordered_container_worker_stride();
        let chunk_len = jobs.len();

        for (chunk_index, job) in jobs.into_iter().enumerate() {
            let idx = (start_idx + (chunk_index / worker_stride)) % self.senders.len();
            let queued = QueuedFmpSendJob::linux_chunked(
                job,
                Arc::clone(&flow),
                chunk_seq,
                chunk_index,
                chunk_len,
            );
            self.dispatch_to_worker(idx, queued);
        }
    }

    #[cfg(target_os = "macos")]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) {
        match self.senders[idx].try_push(job) {
            Ok(()) => {}
            Err(MacWorkerTryPushError::Full(job)) => {
                record_encrypt_worker_queue_full(job.queue_lane());
                if job.queue_lane() == EncryptWorkerLane::Bulk {
                    record_encrypt_worker_backpressure_drop(idx);
                    (*job).complete_sequenced_skip();
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

    #[cfg(not(target_os = "macos"))]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) {
        let sender = &self.senders[idx];
        match sender.try_push(job) {
            Ok(()) => {}
            Err(FairWorkerTryPushError::Full(job)) => {
                record_encrypt_worker_queue_full(job.queue_lane());
                if job.queue_lane() == EncryptWorkerLane::Bulk {
                    record_encrypt_worker_backpressure_drop(idx);
                    (*job).complete_sequenced_skip();
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
type LinuxSendFlowKey = SendDispatchKey;

#[cfg(target_os = "linux")]
#[derive(Default)]
struct LinuxSequencedSendFlows {
    flows: Mutex<HashMap<LinuxSendFlowKey, Arc<LinuxSequencedSendFlow>>>,
    last_prune_ms: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "linux")]
impl LinuxSequencedSendFlows {
    fn flow_for(
        &self,
        key: LinuxSendFlowKey,
        send_target: SelectedSendTarget,
    ) -> Arc<LinuxSequencedSendFlow> {
        let now_ms = linux_now_ms();

        let mut flows = self.flows.lock().expect("linux send flow map poisoned");
        self.prune_idle_locked(&mut flows, now_ms);
        if let Some(flow) = flows.get(&key) {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = LinuxSequencedSendFlow::spawn(key, send_target, now_ms);
        flows.insert(key, Arc::clone(&flow));
        flow
    }

    fn prune_idle_locked(
        &self,
        flows: &mut HashMap<LinuxSendFlowKey, Arc<LinuxSequencedSendFlow>>,
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

        let idle_ms = linux_ordered_send_flow_idle_ms();
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

#[cfg(target_os = "linux")]
fn linux_ordered_container_sender_enabled() -> bool {
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_ORDERED_CONTAINER_SENDER")
            .ok()
            .map(|raw| {
                !matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(false)
    })
}

#[cfg(target_os = "linux")]
fn linux_ordered_container_chunk_size() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_ORDERED_CONTAINER_CHUNK")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(DEFAULT_WORKER_BATCH_SIZE)
            .clamp(1, DEFAULT_WORKER_BATCH_SIZE)
    })
}

#[cfg(target_os = "linux")]
fn linux_ordered_container_worker_stride() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_ORDERED_CONTAINER_WORKER_STRIDE")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 64)
    })
}

#[cfg(target_os = "linux")]
fn linux_ordered_container_sender_batch_size() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_ORDERED_CONTAINER_SEND_BATCH")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(LINUX_UDP_SEND_BATCH_MAX)
            .clamp(1, LINUX_UDP_SEND_BATCH_MAX)
    })
}

#[cfg(target_os = "linux")]
fn linux_ordered_container_pending_cap() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_ORDERED_CONTAINER_PENDING_CAP")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(1024)
            .clamp(1, 32768)
    })
}

#[cfg(target_os = "linux")]
fn linux_ordered_send_flow_idle_ms() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_ORDERED_CONTAINER_FLOW_IDLE_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(120_000)
            .max(10_000)
    })
}

#[cfg(target_os = "linux")]
fn linux_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
struct LinuxSequencedSendFlow {
    key: LinuxSendFlowKey,
    send_target: SelectedSendTarget,
    next_seq: std::sync::atomic::AtomicU64,
    last_used_ms: std::sync::atomic::AtomicU64,
    state: Mutex<LinuxSendFlowState>,
    ready_cv: Condvar,
    space_cv: Condvar,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct LinuxSendFlowState {
    next_send_seq: u64,
    pending: BTreeMap<u64, LinuxPendingChunk>,
    closed: bool,
}

#[cfg(target_os = "linux")]
struct LinuxPendingChunk {
    items: Vec<Option<LinuxSendItem>>,
    ready: usize,
}

#[cfg(target_os = "linux")]
impl LinuxPendingChunk {
    fn new(total: usize) -> Self {
        Self {
            items: (0..total).map(|_| None).collect(),
            ready: 0,
        }
    }

    fn total(&self) -> usize {
        self.items.len()
    }

    fn is_ready(&self) -> bool {
        self.ready == self.items.len()
    }

    fn insert(&mut self, index: usize, item: LinuxSendItem) -> bool {
        if let Some(slot) = self.items.get_mut(index)
            && slot.is_none()
        {
            *slot = Some(item);
            self.ready = self.ready.saturating_add(1);
        }
        self.is_ready()
    }

    fn into_items(self) -> Vec<LinuxSendItem> {
        self.items.into_iter().flatten().collect()
    }
}

#[cfg(target_os = "linux")]
struct LinuxReadyChunk {
    items: Vec<LinuxSendItem>,
}

#[cfg(target_os = "linux")]
struct LinuxChunkPart {
    seq: u64,
    index: usize,
    total: usize,
    item: LinuxSendItem,
}

#[cfg(target_os = "linux")]
impl LinuxChunkPart {
    fn new(seq: u64, index: usize, total: usize, item: LinuxSendItem) -> Self {
        Self {
            seq,
            index,
            total,
            item,
        }
    }
}

#[cfg(target_os = "linux")]
enum LinuxSendItem {
    Packet {
        lane: SelectedSendLane,
        packet: Vec<u8>,
        drop_on_backpressure: bool,
    },
    Skip,
}

#[cfg(target_os = "linux")]
struct LinuxCompletionGroup {
    flow: Arc<LinuxSequencedSendFlow>,
    parts: Vec<LinuxChunkPart>,
}

#[cfg(target_os = "linux")]
impl LinuxCompletionGroup {
    fn new(flow: Arc<LinuxSequencedSendFlow>, part: LinuxChunkPart) -> Self {
        Self {
            flow,
            parts: vec![part],
        }
    }

    fn push(&mut self, flow: &Arc<LinuxSequencedSendFlow>, part: LinuxChunkPart) {
        debug_assert!(
            Arc::ptr_eq(&self.flow, flow),
            "Linux completion group must not merge a different flow owner"
        );
        self.parts.push(part);
    }

    fn complete(self) {
        self.flow.complete_parts(self.parts);
    }
}

#[cfg(target_os = "linux")]
impl LinuxSequencedSendFlow {
    fn spawn(key: LinuxSendFlowKey, send_target: SelectedSendTarget, now_ms: u64) -> Arc<Self> {
        let flow = Arc::new(Self {
            key,
            send_target,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            last_used_ms: std::sync::atomic::AtomicU64::new(now_ms),
            state: Mutex::new(LinuxSendFlowState::default()),
            ready_cv: Condvar::new(),
            space_cv: Condvar::new(),
        });
        let thread_flow = Arc::clone(&flow);
        std::thread::Builder::new()
            .name("fips-linux-ordered-send".to_string())
            .spawn(move || thread_flow.run())
            .expect("failed to spawn fips Linux ordered sender thread");
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

        let state = self.state.lock().expect("linux send flow state poisoned");
        state.pending.is_empty()
            && state.next_send_seq == self.next_seq.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("linux send flow state poisoned");
        state.closed = true;
        drop(state);
        self.ready_cv.notify_one();
        self.space_cv.notify_all();
    }

    fn complete_parts(&self, parts: Vec<LinuxChunkPart>) {
        if parts.is_empty() {
            return;
        }

        let pending_cap = linux_ordered_container_pending_cap();
        let mut state = self.state.lock().expect("linux send flow state poisoned");
        if state.closed {
            return;
        }

        let mut wakes_sender = false;
        for part in parts {
            if part.total == 0 || part.index >= part.total {
                continue;
            }
            while state.pending.len() >= pending_cap
                && part.seq != state.next_send_seq
                && !wakes_sender
                && !state.closed
            {
                state = self
                    .space_cv
                    .wait(state)
                    .expect("linux send flow state poisoned");
            }
            if state.closed {
                return;
            }

            let chunk = state
                .pending
                .entry(part.seq)
                .or_insert_with(|| LinuxPendingChunk::new(part.total));
            if chunk.total() != part.total {
                continue;
            }
            let ready = chunk.insert(part.index, part.item);
            if ready && part.seq == state.next_send_seq {
                wakes_sender = true;
            }
        }

        drop(state);
        if wakes_sender {
            self.ready_cv.notify_one();
        }
    }

    fn run(self: Arc<Self>) {
        trace!(
            target = ?self.key,
            "Linux ordered container sender starting"
        );
        let batch_size = linux_ordered_container_sender_batch_size();

        loop {
            let chunks = {
                let mut state = self.state.lock().expect("linux send flow state poisoned");
                loop {
                    let chunks = pop_linux_ready_chunks_locked(&mut state, batch_size);
                    if !chunks.is_empty() {
                        self.space_cv.notify_all();
                        break chunks;
                    }
                    if state.closed {
                        return;
                    }
                    state = self
                        .ready_cv
                        .wait(state)
                        .expect("linux send flow state poisoned");
                }
            };

            self.flush_ready_chunks(chunks, batch_size);
        }
    }

    fn flush_ready_chunks(&self, chunks: Vec<LinuxReadyChunk>, packet_capacity: usize) {
        let mut groups: Vec<SelectedSendBatch> = Vec::with_capacity(1);
        let target_key = self.send_target.key();
        for chunk in chunks {
            for item in chunk.items {
                match item {
                    LinuxSendItem::Packet {
                        lane,
                        packet,
                        drop_on_backpressure,
                    } => push_selected_send_batch_with_lane_and_capacity(
                        &mut groups,
                        self.send_target.clone(),
                        target_key,
                        lane,
                        packet,
                        drop_on_backpressure,
                        packet_capacity,
                    ),
                    LinuxSendItem::Skip => {}
                }
            }
        }
        if groups.is_empty() {
            return;
        }

        record_selected_send_groups(&groups);
        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
        if let Err(err) = flush_linux_send_groups_sync(groups) {
            debug!(
                target = ?self.key,
                error = %err,
                "Linux ordered container send failed"
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn pop_linux_ready_chunks_locked(
    state: &mut LinuxSendFlowState,
    packet_budget: usize,
) -> Vec<LinuxReadyChunk> {
    let packet_budget = packet_budget.max(1);
    let mut chunks = Vec::new();
    let mut packets = 0usize;

    loop {
        let next = state.next_send_seq;
        let Some(chunk) = state.pending.get(&next) else {
            break;
        };
        if !chunk.is_ready() {
            break;
        }
        let chunk_packets = chunk.total();
        if !chunks.is_empty() && packets.saturating_add(chunk_packets) > packet_budget {
            break;
        }
        let chunk = state
            .pending
            .remove(&next)
            .expect("checked pending chunk exists");
        state.next_send_seq = next.wrapping_add(1);
        packets = packets.saturating_add(chunk_packets);
        chunks.push(LinuxReadyChunk {
            items: chunk.into_items(),
        });
        if packets >= packet_budget {
            break;
        }
    }

    chunks
}

#[cfg(target_os = "linux")]
fn push_linux_completion(
    groups: &mut Vec<LinuxCompletionGroup>,
    flow: Arc<LinuxSequencedSendFlow>,
    part: LinuxChunkPart,
) {
    if let Some(group) = groups
        .iter_mut()
        .find(|group| Arc::ptr_eq(&group.flow, &flow))
    {
        group.push(&flow, part);
    } else {
        groups.push(LinuxCompletionGroup::new(flow, part));
    }
}

#[cfg(target_os = "macos")]
type MacSendFlowKey = SendTargetKey;

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
        let key = job.send_target_key();

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
    // Ordered mode parallelizes one peer's FMP AEAD while preserving UDP order,
    // but the extra flow map + sender-thread handoff regressed the measured
    // MacBook Wi-Fi -> Ethernet path. Keep it opt-in for AEAD-bound comparisons;
    // the default keeps packets on the worker selected by send target.
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_ORDERED_SENDER")
            .ok()
            .map(|raw| {
                !matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(false)
    })
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
            .name(format!("fips-mac-send-{}", key.socket_fd))
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

    fn run(self: Arc<Self>) {
        trace!(
            socket_fd = self.key.socket_fd,
            connected_fd = ?self.key.connected_fd,
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
                            socket_fd = self.key.socket_fd,
                            connected_fd = ?self.key.connected_fd,
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
