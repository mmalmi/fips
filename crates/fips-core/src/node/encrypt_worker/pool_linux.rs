#[cfg(target_os = "linux")]
type LinuxSendFlowKey = SendTargetKey;

#[cfg(target_os = "linux")]
#[derive(Default)]
struct LinuxSequencedSendFlows {
    flows: Mutex<HashMap<LinuxSendFlowKey, Arc<LinuxSequencedSendFlow>>>,
    last_prune_ms: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "linux")]
impl LinuxSequencedSendFlows {
    fn flow_for(&self, job: &FmpSendJob) -> Arc<LinuxSequencedSendFlow> {
        let now_ms = linux_now_ms();
        let key = job.send_target_key();

        let mut flows = self.flows.lock().expect("linux send flow map poisoned");
        self.prune_idle_locked(&mut flows, now_ms);
        if let Some(flow) = flows.get(&key) {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = LinuxSequencedSendFlow::spawn(key, job.send_target.clone(), now_ms);
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

        let idle_ms = linux_send_flow_idle_ms();
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
impl EncryptWorkerPool {
    fn dispatch_linux_ordered_bulk_batch(&self, jobs: Vec<FmpSendJob>) {
        if jobs.is_empty() {
            return;
        }
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping bulk batch");
            return;
        }

        let mut run: Vec<FmpSendJob> = Vec::new();
        let mut run_key: Option<SendTargetKey> = None;
        for job in jobs {
            if !job.bulk_endpoint_data {
                self.dispatch_linux_ordered_bulk_run(std::mem::take(&mut run));
                run_key = None;
                self.dispatch(job);
                continue;
            }

            let key = job.send_target_key();
            if run_key.is_some_and(|current| current != key) {
                self.dispatch_linux_ordered_bulk_run(std::mem::take(&mut run));
            }
            if run_key != Some(key) {
                run_key = Some(key);
            }
            run.push(job);
        }
        self.dispatch_linux_ordered_bulk_run(run);
    }

    fn dispatch_linux_ordered_bulk_run(&self, jobs: Vec<FmpSendJob>) {
        if jobs.is_empty() {
            return;
        }

        let flow = self.linux_senders.flow_for(&jobs[0]);
        let seq_base = flow.reserve_seq_run(jobs.len());
        let packet_base = self
            .next_worker
            .fetch_add(jobs.len(), std::sync::atomic::Ordering::Relaxed);
        let stride = linux_worker_stride();

        for (offset, job) in jobs.into_iter().enumerate() {
            let idx = linux_ordered_worker_index(
                packet_base,
                offset,
                stride,
                self.senders.len(),
            );
            let seq = seq_base.wrapping_add(offset as u64);
            self.dispatch_to_worker(
                idx,
                QueuedFmpSendJob::linux_sequenced_with_seq(job, Arc::clone(&flow), seq),
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_ordered_sender_enabled() -> bool {
    // Opt-in Linux path that mirrors the wireguard-go packet mover shape:
    // route/nonce on rx_loop, parallel FMP AEAD on workers, one ordered
    // sender per kernel target. Keep priority/control packets on the direct
    // worker path so bulk sequence gaps cannot stall liveness or rekey work.
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_ORDERED_SENDER")
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
fn linux_worker_stride() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_WORKER_STRIDE")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            // Packet-level round-robin fans AEAD work out, but it destroys the
            // worker/GSO batch shape. Default to one worker drain turn per
            // target before moving to the next worker.
            .unwrap_or_else(worker_batch_size)
            .clamp(1, 64)
    })
}

#[cfg(target_os = "linux")]
fn linux_ordered_send_batch_size() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_ORDERED_SEND_BATCH")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or_else(worker_batch_size)
            .clamp(1, LINUX_UDP_SEND_BATCH_MAX)
    })
}

#[cfg(target_os = "linux")]
fn linux_ordered_worker_index(
    packet_base: usize,
    offset: usize,
    stride: usize,
    worker_count: usize,
) -> usize {
    debug_assert!(worker_count > 0);
    let stride = stride.max(1);
    ((packet_base.wrapping_add(offset)) / stride) % worker_count
}

#[cfg(target_os = "linux")]
fn linux_send_flow_idle_ms() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_SEND_FLOW_IDLE_MS")
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
    pending: BTreeMap<u64, LinuxSendItem>,
    closed: bool,
}

#[cfg(target_os = "linux")]
struct LinuxCompletionGroup {
    flow_key: LinuxSendFlowKey,
    flow: Arc<LinuxSequencedSendFlow>,
    items: Vec<(u64, LinuxSendItem)>,
}

#[cfg(target_os = "linux")]
enum LinuxSendItem {
    Packet {
        packet: Vec<u8>,
        drop_on_backpressure: bool,
    },
    Skip,
}

#[cfg(target_os = "linux")]
impl LinuxCompletionGroup {
    fn new(flow: Arc<LinuxSequencedSendFlow>, seq: u64, item: LinuxSendItem) -> Self {
        let flow_key = flow.key;
        Self {
            flow_key,
            flow,
            items: vec![(seq, item)],
        }
    }

    fn push(&mut self, flow: &Arc<LinuxSequencedSendFlow>, seq: u64, item: LinuxSendItem) {
        debug_assert_eq!(
            self.flow_key, flow.key,
            "Linux completion group must keep the queued flow key"
        );
        debug_assert!(
            Arc::ptr_eq(&self.flow, flow),
            "Linux completion group must not merge a different flow owner"
        );
        self.items.push((seq, item));
    }

    fn complete(self) {
        self.flow.complete_many(self.items);
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
            .name(format!("fips-linux-send-{}", key.socket_fd))
            .spawn(move || thread_flow.run())
            .expect("failed to spawn fips Linux send thread");
        flow
    }

    #[cfg(test)]
    fn new_for_test(key: LinuxSendFlowKey, send_target: SelectedSendTarget) -> Self {
        Self {
            key,
            send_target,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            last_used_ms: std::sync::atomic::AtomicU64::new(0),
            state: Mutex::new(LinuxSendFlowState::default()),
            ready_cv: Condvar::new(),
            space_cv: Condvar::new(),
        }
    }

    fn reserve_seq(&self) -> u64 {
        self.next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn reserve_seq_run(&self, count: usize) -> u64 {
        debug_assert!(count > 0);
        self.next_seq
            .fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed)
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

    fn complete_many(&self, items: Vec<(u64, LinuxSendItem)>) {
        const PENDING_CAP: usize = 4096;
        if items.is_empty() {
            return;
        }

        let mut state = self.state.lock().expect("linux send flow state poisoned");
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
                    .expect("linux send flow state poisoned");
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
            "Linux ordered UDP sender starting"
        );

        while let Some(items) = self.pop_ready_items(linux_ordered_send_batch_size()) {
            let mut groups: Vec<SelectedSendBatch> = Vec::with_capacity(1);
            let group_capacity = items.len().max(1);
            for item in items {
                match item {
                    LinuxSendItem::Packet {
                        packet,
                        drop_on_backpressure,
                    } => push_selected_send_batch_with_capacity(
                        &mut groups,
                        self.send_target.clone(),
                        self.key,
                        packet,
                        drop_on_backpressure,
                        group_capacity,
                    ),
                    LinuxSendItem::Skip => {}
                }
            }
            if groups.is_empty() {
                continue;
            }

            record_selected_send_groups(&groups);
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
            if let Err(err) = flush_linux_send_groups_sync(groups) {
                debug!(
                    socket_fd = self.key.socket_fd,
                    connected_fd = ?self.key.connected_fd,
                    dest = %self.send_target.dest_addr(),
                    error = %err,
                    "Linux ordered UDP send failed"
                );
            }
        }
    }

    fn pop_ready_items(&self, max: usize) -> Option<Vec<LinuxSendItem>> {
        let max = max.max(1);
        let mut state = self.state.lock().expect("linux send flow state poisoned");
        loop {
            let next = state.next_send_seq;
            if let Some(item) = state.pending.remove(&next) {
                let mut items = Vec::with_capacity(max);
                items.push(item);
                state.next_send_seq = next.wrapping_add(1);

                while items.len() < max {
                    let next = state.next_send_seq;
                    let Some(item) = state.pending.remove(&next) else {
                        break;
                    };
                    items.push(item);
                    state.next_send_seq = next.wrapping_add(1);
                }

                self.space_cv.notify_all();
                return Some(items);
            }
            if state.closed {
                return None;
            }
            state = self
                .ready_cv
                .wait(state)
                .expect("linux send flow state poisoned");
        }
    }
}

#[cfg(target_os = "linux")]
fn push_linux_completion(
    groups: &mut Vec<LinuxCompletionGroup>,
    flow: Arc<LinuxSequencedSendFlow>,
    seq: u64,
    item: LinuxSendItem,
) {
    if let Some(group) = groups
        .iter_mut()
        .find(|group| Arc::ptr_eq(&group.flow, &flow))
    {
        group.push(&flow, seq, item);
    } else {
        groups.push(LinuxCompletionGroup::new(flow, seq, item));
    }
}
