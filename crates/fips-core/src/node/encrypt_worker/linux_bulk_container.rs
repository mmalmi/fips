#[cfg(target_os = "linux")]
#[derive(Default)]
struct LinuxBulkSendFlows {
    flows: Mutex<HashMap<SendTargetKey, Arc<LinuxBulkSendFlow>>>,
    last_prune_ms: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "linux")]
impl LinuxBulkSendFlows {
    fn flow_for(&self, job: &FmpSendJob) -> Arc<LinuxBulkSendFlow> {
        let now_ms = linux_now_ms();
        let key = job.send_target_key();

        let mut flows = self.flows.lock().expect("linux send flow map poisoned");
        self.prune_idle_locked(&mut flows, now_ms);
        if let Some(flow) = flows.get(&key) {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = LinuxBulkSendFlow::spawn(key, job.send_target.clone(), now_ms);
        flows.insert(key, Arc::clone(&flow));
        flow
    }

    fn prune_idle_locked(
        &self,
        flows: &mut HashMap<SendTargetKey, Arc<LinuxBulkSendFlow>>,
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

        let idle_ms = linux_bulk_send_flow_idle_ms();
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
struct LinuxBulkSendFlow {
    key: SendTargetKey,
    send_target: SelectedSendTarget,
    tx: Sender<Arc<LinuxBulkSendContainer>>,
    queued: std::sync::atomic::AtomicUsize,
    active: std::sync::atomic::AtomicUsize,
    last_used_ms: std::sync::atomic::AtomicU64,
    closed: std::sync::atomic::AtomicBool,
}

#[cfg(target_os = "linux")]
impl LinuxBulkSendFlow {
    fn spawn(key: SendTargetKey, send_target: SelectedSendTarget, now_ms: u64) -> Arc<Self> {
        let (tx, rx) = bounded(linux_bulk_container_queue_cap());
        let flow = Arc::new(Self {
            key,
            send_target,
            tx,
            queued: std::sync::atomic::AtomicUsize::new(0),
            active: std::sync::atomic::AtomicUsize::new(0),
            last_used_ms: std::sync::atomic::AtomicU64::new(now_ms),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let thread_flow = Arc::clone(&flow);
        std::thread::Builder::new()
            .name(format!("fips-linux-bulk-send-{}", key.socket_fd))
            .spawn(move || thread_flow.run(rx))
            .expect("failed to spawn fips Linux bulk send thread");
        flow
    }

    fn mark_used(&self, now_ms: u64) {
        self.last_used_ms
            .store(now_ms, std::sync::atomic::Ordering::Relaxed);
    }

    fn try_enqueue(&self, container: Arc<LinuxBulkSendContainer>) -> bool {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        if self.inflight_containers() >= linux_bulk_container_inflight_cap() {
            return false;
        }

        self.queued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match self.tx.try_send(container) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.queued
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                false
            }
        }
    }

    fn inflight_containers(&self) -> usize {
        self.queued
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_add(self.active.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed)
            || self.queued.load(std::sync::atomic::Ordering::Relaxed) != 0
            || self.active.load(std::sync::atomic::Ordering::Relaxed) != 0
        {
            return false;
        }
        let last_used = self.last_used_ms.load(std::sync::atomic::Ordering::Relaxed);
        now_ms.saturating_sub(last_used) >= idle_ms
    }

    fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn run(self: Arc<Self>, rx: Receiver<Arc<LinuxBulkSendContainer>>) {
        trace!(
            socket_fd = self.key.socket_fd,
            connected_fd = ?self.key.connected_fd,
            dest = %self.send_target.dest_addr(),
            "Linux bulk container sender starting"
        );

        loop {
            match rx.recv_timeout(std::time::Duration::from_millis(250)) {
                Ok(container) => {
                    self.queued
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    self.active
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    crate::perf_profile::record_since_count(
                        crate::perf_profile::Stage::FmpLinuxBulkContainerQueueWait,
                        container.enqueued_at(),
                        1,
                    );
                    container.wait_and_send(&self.send_target, self.key);
                    self.active
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    if self.closed.load(std::sync::atomic::Ordering::Relaxed)
                        && self.queued.load(std::sync::atomic::Ordering::Relaxed) == 0
                        && self.active.load(std::sync::atomic::Ordering::Relaxed) == 0
                    {
                        return;
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct LinuxBulkSendContainer {
    state: Mutex<LinuxBulkSendContainerState>,
    ready_cv: Condvar,
    enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

#[cfg(target_os = "linux")]
struct LinuxBulkSendContainerState {
    remaining: usize,
    slots: Vec<LinuxBulkSendSlot>,
}

#[cfg(target_os = "linux")]
enum LinuxBulkSendSlot {
    Pending,
    Packet {
        packet: Vec<u8>,
        drop_on_backpressure: bool,
    },
    Skip,
}

#[cfg(target_os = "linux")]
impl LinuxBulkSendContainer {
    fn new(slot_count: usize) -> Self {
        let mut slots = Vec::with_capacity(slot_count);
        slots.resize_with(slot_count, || LinuxBulkSendSlot::Pending);
        Self {
            state: Mutex::new(LinuxBulkSendContainerState {
                remaining: slot_count,
                slots,
            }),
            ready_cv: Condvar::new(),
            enqueued_at: crate::perf_profile::stamp(),
        }
    }

    fn enqueued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        self.enqueued_at
    }

    fn complete_packet(&self, slot: usize, packet: Vec<u8>, drop_on_backpressure: bool) {
        self.complete_slot(
            slot,
            LinuxBulkSendSlot::Packet {
                packet,
                drop_on_backpressure,
            },
        );
    }

    fn skip(&self, slot: usize) {
        self.complete_slot(slot, LinuxBulkSendSlot::Skip);
    }

    fn complete_slot(&self, slot: usize, item: LinuxBulkSendSlot) {
        let skipped = matches!(item, LinuxBulkSendSlot::Skip);
        let (completed, notify_ready, first_completed, all_completed) = {
            let mut state = self
                .state
                .lock()
                .expect("linux bulk container state poisoned");
            let mut completed = false;
            let mut first_completed = false;
            let was_first_pending = state.remaining == state.slots.len();
            if let Some(slot_state) = state.slots.get_mut(slot)
                && matches!(slot_state, LinuxBulkSendSlot::Pending)
            {
                *slot_state = item;
                completed = true;
                first_completed = was_first_pending;
            }
            if completed {
                state.remaining = state.remaining.saturating_sub(1);
            }
            (
                completed,
                completed && state.remaining == 0,
                first_completed,
                completed && state.remaining == 0,
            )
        };
        if completed && skipped {
            crate::perf_profile::record_fmp_linux_bulk_container_skipped_packet();
        }
        if first_completed {
            crate::perf_profile::record_since_count(
                crate::perf_profile::Stage::FmpLinuxBulkContainerFirstSlotWait,
                self.enqueued_at,
                1,
            );
        }
        if all_completed {
            crate::perf_profile::record_since_count(
                crate::perf_profile::Stage::FmpLinuxBulkContainerAllSlotsWait,
                self.enqueued_at,
                1,
            );
        }
        if notify_ready {
            self.ready_cv.notify_one();
        }
    }

    fn wait_and_send(&self, send_target: &SelectedSendTarget, target_key: SendTargetKey) {
        let ready_wait_start = crate::perf_profile::stamp();
        let slots = {
            let mut state = self
                .state
                .lock()
                .expect("linux bulk container state poisoned");
            while state.remaining > 0 {
                state = self
                    .ready_cv
                    .wait(state)
                    .expect("linux bulk container state poisoned");
            }
            crate::perf_profile::record_since_count(
                crate::perf_profile::Stage::FmpLinuxBulkContainerReadyWait,
                ready_wait_start,
                1,
            );
            std::mem::take(&mut state.slots)
        };

        let packet_capacity = slots.len();
        let mut groups: Vec<SelectedSendBatch> = Vec::with_capacity(1);
        for slot in slots {
            let LinuxBulkSendSlot::Packet {
                packet,
                drop_on_backpressure,
            } = slot
            else {
                continue;
            };
            push_uniform_target_send_batch_with_capacity(
                &mut groups,
                send_target,
                target_key,
                packet,
                true,
                drop_on_backpressure,
                packet_capacity,
            );
        }
        if groups.is_empty() {
            crate::perf_profile::record_fmp_linux_bulk_container_empty();
            return;
        }

        record_selected_send_groups(&groups);
        let udp_send_packet_count = groups
            .iter()
            .map(SelectedSendBatch::packet_count)
            .sum::<usize>();
        crate::perf_profile::record_fmp_linux_bulk_container_sent(udp_send_packet_count);
        let _bulk_send_t = crate::perf_profile::BatchTimer::start(
            crate::perf_profile::Stage::FmpLinuxBulkContainerSend,
            udp_send_packet_count,
        );
        let _t = crate::perf_profile::BatchTimer::start(
            crate::perf_profile::Stage::UdpSend,
            udp_send_packet_count,
        );
        if let Err(err) = flush_linux_send_batches_sync(groups) {
            debug!(
                socket_fd = target_key.socket_fd,
                connected_fd = ?target_key.connected_fd,
                dest = %target_key.dest_addr,
                error = %err,
                "Linux bulk container send failed"
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_bulk_container_sender_enabled() -> bool {
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| {
        parse_linux_bulk_container_sender_enabled(
            std::env::var("FIPS_LINUX_BULK_CONTAINERS").ok().as_deref(),
        )
    })
}

#[cfg_attr(not(all(test, target_os = "linux")), allow(dead_code))]
fn parse_linux_bulk_container_sender_enabled(raw: Option<&str>) -> bool {
    raw.map(|raw| {
        !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        )
    })
    .unwrap_or(true)
}

#[cfg(target_os = "linux")]
fn linux_bulk_container_min_packets() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_BULK_CONTAINER_MIN_PACKETS")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(8)
            .clamp(2, 256)
    })
}

#[cfg(target_os = "linux")]
fn linux_bulk_container_queue_cap() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_BULK_CONTAINER_QUEUE_CAP")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(32)
            .clamp(1, 4096)
    })
}

#[cfg(target_os = "linux")]
fn linux_bulk_container_inflight_cap() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        parse_linux_bulk_container_inflight_cap(
            std::env::var("FIPS_LINUX_BULK_CONTAINER_INFLIGHT_CAP")
                .ok()
                .as_deref(),
        )
    })
}

#[cfg_attr(not(all(test, target_os = "linux")), allow(dead_code))]
fn parse_linux_bulk_container_inflight_cap(raw: Option<&str>) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(64)
        .clamp(1, 4096)
}

#[cfg(target_os = "linux")]
fn linux_bulk_send_flow_idle_ms() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_BULK_SEND_FLOW_IDLE_MS")
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
