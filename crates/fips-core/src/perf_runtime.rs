static TOTAL_NS: [AtomicU64; N_STAGES] = [const { AtomicU64::new(0) }; N_STAGES];
static COUNT: [AtomicU64; N_STAGES] = [const { AtomicU64::new(0) }; N_STAGES];
static MAX_NS: [AtomicU64; N_STAGES] = [const { AtomicU64::new(0) }; N_STAGES];
static HIST: [AtomicU64; N_STAGES * HIST_BUCKETS] =
    [const { AtomicU64::new(0) }; N_STAGES * HIST_BUCKETS];
static EVENTS: [AtomicU64; N_EVENTS] = [const { AtomicU64::new(0) }; N_EVENTS];
static TRACE_EPOCH: OnceLock<Instant> = OnceLock::new();

/// Compact monotonic timestamp carried by packet/job queue handoffs.
///
/// `Instant` is 16 bytes on common targets. Hot-path packets and worker jobs
/// only need elapsed time relative to this process, so store a non-zero
/// nanosecond offset from one process-local epoch instead. `Option<TraceStamp>`
/// stays 8 bytes thanks to `NonZeroU64`'s niche.
#[doc(hidden)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TraceStamp(NonZeroU64);

impl TraceStamp {
    fn now() -> Self {
        let elapsed = trace_elapsed_ns().saturating_add(1).max(1);
        Self(NonZeroU64::new(elapsed).unwrap_or(NonZeroU64::MAX))
    }

    fn elapsed_ns(self) -> u64 {
        trace_elapsed_ns().saturating_sub(self.0.get().saturating_sub(1))
    }
}

fn trace_epoch() -> Instant {
    *TRACE_EPOCH.get_or_init(Instant::now)
}

fn trace_elapsed_ns() -> u64 {
    Instant::now()
        .saturating_duration_since(trace_epoch())
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

/// True iff perf/pipeline tracing is enabled. Read once at startup so
/// the per-packet check is a single cached load.
pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        ["FIPS_PERF", "FIPS_PIPELINE_TRACE", "NVPN_PIPELINE_TRACE"]
            .into_iter()
            .any(|key| {
                std::env::var(key)
                    .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
            })
    })
}

/// Capture a timestamp for a future queue-wait measurement. Returns
/// `None` when tracing is disabled so callers can store it cheaply in
/// packet/job structs without paying `Instant::now()` in production.
#[inline]
pub(crate) fn stamp() -> Option<TraceStamp> {
    if enabled() {
        Some(TraceStamp::now())
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) fn test_stamp() -> TraceStamp {
    TraceStamp::now()
}

#[inline]
fn record_count_enabled(stage: Stage, elapsed_ns: u64, count: u64) {
    debug_assert!(count > 0);
    let elapsed_ns = elapsed_ns.max(1);
    let bucket = bucket_for_ns(elapsed_ns);
    record_count_sample(stage, elapsed_ns, count, bucket);
}

#[inline]
fn record_count_sample(stage: Stage, elapsed_ns: u64, count: u64, bucket: usize) {
    let idx = stage as usize;
    TOTAL_NS[idx].fetch_add(elapsed_ns.saturating_mul(count), Relaxed);
    MAX_NS[idx].fetch_max(elapsed_ns, Relaxed);
    HIST[(idx * HIST_BUCKETS) + bucket].fetch_add(count, Relaxed);
    COUNT[idx].fetch_add(count, Release);
}

#[inline]
pub(crate) fn record_since(stage: Stage, start: Option<TraceStamp>) {
    let Some(start) = start else {
        return;
    };
    if !enabled() {
        return;
    }
    record_count_enabled(stage, start.elapsed_ns(), 1);
}

#[inline]
pub(crate) fn record_since_count(stage: Stage, start: Option<TraceStamp>, count: u64) {
    if count == 0 {
        return;
    }
    let Some(start) = start else {
        return;
    };
    if !enabled() {
        return;
    }
    record_count_enabled(stage, start.elapsed_ns(), count);
}

/// Record one queue wait into aggregate + priority/bulk split counters.
///
/// Queue waits are among the hottest tracing points. Compute elapsed time and
/// histogram bucket once per observed handoff, then fan the same sample into
/// aggregate and lane counters.
#[inline]
pub(crate) fn record_since_split_count(
    total_stage: Stage,
    priority_stage: Stage,
    bulk_stage: Stage,
    start: Option<TraceStamp>,
    total_count: u64,
    priority_count: u64,
    bulk_count: u64,
) {
    debug_assert_eq!(
        priority_count.saturating_add(bulk_count),
        total_count,
        "queue wait split counts should add up to the aggregate count"
    );
    if total_count == 0 {
        return;
    }
    let Some(start) = start else {
        return;
    };
    if !enabled() {
        return;
    }
    let elapsed_ns = start.elapsed_ns().max(1);
    let bucket = bucket_for_ns(elapsed_ns);
    record_count_sample(total_stage, elapsed_ns, total_count, bucket);
    if priority_count > 0 {
        record_count_sample(priority_stage, elapsed_ns, priority_count, bucket);
    }
    if bulk_count > 0 {
        record_count_sample(bulk_stage, elapsed_ns, bulk_count, bucket);
    }
}

#[inline]
pub fn record_event(event: Event) {
    record_event_count(event, 1);
}

pub fn record_event_count(event: Event, count: u64) {
    if !enabled() || count == 0 {
        return;
    }
    record_event_count_sample(event, count);
}

#[inline]
#[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
pub(crate) fn record_tun_outbound_admission_drop() {
    record_event(Event::PendingTunPacketDropped);
    record_event(Event::TunOutboundAdmissionDropped);
}

#[inline]
pub(crate) fn record_pending_tun_session_oldest_drop() {
    record_event(Event::PendingTunPacketDropped);
    record_event(Event::PendingTunSessionOldestDropped);
}

#[inline]
pub(crate) fn record_pending_tun_session_stale_drops(count: u64) {
    record_event_count(Event::PendingTunPacketDropped, count);
    record_event_count(Event::PendingTunSessionStaleDropped, count);
}

#[inline]
pub(crate) fn record_udp_kernel_drops(drops: u64) {
    record_event_count(Event::UdpKernelDropped, drops);
}

#[inline]
pub(crate) fn record_udp_socket_kernel_drops(drops: u64) {
    record_event_count(Event::UdpSocketKernelDropped, drops);
}

#[inline]
pub(crate) fn record_udp_namespace_rcvbuf_errors(drops: u64) {
    record_event_count(Event::UdpNamespaceRcvbufErrors, drops);
}

#[inline]
#[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
pub(crate) fn record_tun_read_packet(bytes: usize) {
    if !enabled() {
        return;
    }
    record_event_count_sample(Event::TunReadPackets, 1);
    record_event_count_sample(Event::TunReadBytes, bytes as u64);
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_tun_read_frame(bytes: usize) {
    if !enabled() {
        return;
    }
    record_event_count_sample(Event::TunReadFrames, 1);
    record_event_count_sample(Event::TunReadFrameBytes, bytes as u64);
}

#[inline]
#[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
pub(crate) fn record_tun_write_packet(bytes: usize) {
    if !enabled() {
        return;
    }
    record_event_count_sample(Event::TunWritePackets, 1);
    record_event_count_sample(Event::TunWriteBytes, bytes as u64);
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_tun_write_frame(bytes: usize) {
    if !enabled() {
        return;
    }
    record_event_count_sample(Event::TunWriteFrames, 1);
    record_event_count_sample(Event::TunWriteFrameBytes, bytes as u64);
}

/// Record the prepared dataplane open chunk width before inline AEAD execution.
///
/// These counters describe the natural work unit available to a future
/// stateless crypto worker pool. They stay trace-gated and do not imply a
/// second packet path.
#[inline]
pub(crate) fn record_dataplane_crypto_open_batch(packets: usize) {
    record_dataplane_crypto_batch(
        Event::DataplaneCryptoOpenBatch,
        Event::DataplaneCryptoOpenPackets,
        packets,
    );
}

/// Record the prepared dataplane seal chunk width before inline AEAD execution.
#[inline]
pub(crate) fn record_dataplane_crypto_seal_batch(packets: usize) {
    record_dataplane_crypto_batch(
        Event::DataplaneCryptoSealBatch,
        Event::DataplaneCryptoSealPackets,
        packets,
    );
}

#[inline]
fn record_dataplane_crypto_batch(batch_event: Event, packet_event: Event, packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(batch_event, 1);
    record_event_count_sample(packet_event, packets as u64);
    let (single, ge8, ge32, ge64) = dataplane_crypto_batch_bucket_flags(packets);
    if single {
        record_event_count_sample(Event::DataplaneCryptoBatchSingle, 1);
    }
    if ge8 {
        record_event_count_sample(Event::DataplaneCryptoBatchGe8, 1);
    }
    if ge32 {
        record_event_count_sample(Event::DataplaneCryptoBatchGe32, 1);
    }
    if ge64 {
        record_event_count_sample(Event::DataplaneCryptoBatchGe64, 1);
    }
}

#[inline]
fn dataplane_crypto_batch_bucket_flags(packets: usize) -> (bool, bool, bool, bool) {
    (packets == 1, packets >= 8, packets >= 32, packets >= 64)
}

#[inline]
pub(crate) fn record_dataplane_aead_ready_slot(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::DataplaneAeadReadySlots, 1);
    record_event_count_sample(Event::DataplaneAeadReadySlotPackets, packets as u64);
}

#[inline]
pub(crate) fn record_dataplane_aead_prepared_job(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::DataplaneAeadPreparedJob, 1);
    record_event_count_sample(Event::DataplaneAeadPreparedJobPackets, packets as u64);
}

#[inline]
pub(crate) fn record_dataplane_fast_ingress_owner_run(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::DataplaneFastIngressOwnerRuns, 1);
    record_event_count_sample(Event::DataplaneFastIngressOwnerRunPackets, packets as u64);
}

#[inline]
pub(crate) fn record_dataplane_established_fsp_data_retire_run(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::DataplaneEstablishedFspDataRetireRuns, 1);
    record_event_count_sample(
        Event::DataplaneEstablishedFspDataRetirePackets,
        packets as u64,
    );
}

#[inline]
pub(crate) fn record_dataplane_live_completions_retired(count: usize) {
    record_event_count(Event::DataplaneLiveCompletionsRetired, count as u64);
}

#[inline]
pub(crate) fn record_dataplane_live_output_batch(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::DataplaneLiveOutputBatch, 1);
    record_event_count_sample(Event::DataplaneLiveOutputBatchPackets, packets as u64);
}

#[inline]
#[cfg(test)]
fn record_wait_threshold(event: Event, elapsed_ns: u64, count: u64, threshold_ns: u64) {
    if elapsed_ns >= threshold_ns {
        record_event_count_sample(event, count);
    }
}

/// Record Linux `sendmmsg(2)` UDP batches submitted by the dataplane send side.
#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_udp_send_sendmmsg_batch(packets: usize) {
    record_udp_send_batch(
        Event::UdpSendSendmmsgBatch,
        Event::UdpSendSendmmsgPackets,
        packets,
    );
    record_udp_send_batch_tail_buckets(
        packets,
        Event::UdpSendSendmmsgBatchGe32,
        Event::UdpSendSendmmsgBatchGe48,
        Event::UdpSendSendmmsgBatchEq64,
    );
}

/// Record Linux `sendmsg(2)+UDP_SEGMENT` batches submitted by the dataplane send side.
#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_udp_send_gso_batch(packets: usize) {
    record_udp_send_batch(Event::UdpSendGsoBatch, Event::UdpSendGsoPackets, packets);
    record_udp_send_batch_tail_buckets(
        packets,
        Event::UdpSendGsoBatchGe32,
        Event::UdpSendGsoBatchGe48,
        Event::UdpSendGsoBatchEq64,
    );
}

/// Record Darwin `sendmsg_x(2)` UDP batches submitted by the dataplane send side.
#[inline]
#[cfg(target_os = "macos")]
pub(crate) fn record_udp_send_sendmsgx_batch(packets: usize) {
    record_udp_send_batch(
        Event::UdpSendSendmsgxBatch,
        Event::UdpSendSendmsgxPackets,
        packets,
    );
    record_udp_send_batch_tail_buckets(
        packets,
        Event::UdpSendSendmsgxBatchGe32,
        Event::UdpSendSendmsgxBatchGe48,
        Event::UdpSendSendmsgxBatchEq64,
    );
}

/// Record Darwin `recvmsg_x(2)` UDP batches drained by the transport receive side.
#[inline]
#[cfg(target_os = "macos")]
pub(crate) fn record_udp_recv_recvmsgx_batch(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::UdpRecvRecvmsgxBatch, 1);
    record_event_count_sample(Event::UdpRecvRecvmsgxPackets, packets as u64);
    if packets == 1 {
        record_event_count_sample(Event::UdpRecvRecvmsgxBatchEq1, 1);
    }
    if packets >= 2 {
        record_event_count_sample(Event::UdpRecvRecvmsgxBatchGe2, 1);
    }
    if packets >= 8 {
        record_event_count_sample(Event::UdpRecvRecvmsgxBatchGe8, 1);
    }
}

#[inline]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn record_udp_send_batch(batch_event: Event, packet_event: Event, packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(batch_event, 1);
    record_event_count_sample(packet_event, packets as u64);
}

#[inline]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn record_udp_send_batch_tail_buckets(
    packets: usize,
    ge32_event: Event,
    ge48_event: Event,
    eq64_event: Event,
) {
    if !enabled() || packets == 0 {
        return;
    }
    let (ge32, ge48, eq64) = udp_send_batch_tail_bucket_flags(packets);
    if ge32 {
        record_event_count_sample(ge32_event, 1);
    }
    if ge48 {
        record_event_count_sample(ge48_event, 1);
    }
    if eq64 {
        record_event_count_sample(eq64_event, 1);
    }
}

/// Record Linux UDP_GRO receives split back into FIPS datagrams by userspace.
#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_udp_recv_gro_split(segments: usize, bytes: usize) {
    if !enabled() || segments == 0 || bytes == 0 {
        return;
    }
    record_event_count_sample(Event::UdpRecvGroBatch, 1);
    record_event_count_sample(Event::UdpRecvGroPackets, segments as u64);
    record_event_count_sample(Event::UdpRecvGroBytes, bytes as u64);
}

/// Record ordinary Linux UDP receives that do not need userspace GRO splitting.
#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_udp_recv_plain_packet() {
    record_event(Event::UdpRecvPlainPackets);
}

#[inline]
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn udp_send_batch_tail_bucket_flags(packets: usize) -> (bool, bool, bool) {
    (packets >= 32, packets >= 48, packets >= 64)
}

#[inline]
fn record_event_count_sample(event: Event, count: u64) {
    EVENTS[event as usize].fetch_add(count, Relaxed);
}

/// RAII timer - `drop` records the elapsed time into the stage.
/// Use:
/// ```ignore
/// let _t = profile::Timer::start(Stage::DataplaneAeadOpen);
/// // ... AEAD work ...
/// ```
pub struct Timer {
    stage: Stage,
    start: Option<Instant>,
}

impl Timer {
    #[inline]
    pub fn start(stage: Stage) -> Self {
        let start = if enabled() {
            Some(Instant::now())
        } else {
            None
        };
        Self { stage, start }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(t0) = self.start {
            let ns = t0.elapsed().as_nanos() as u64;
            record_count_enabled(self.stage, ns, 1);
        }
    }
}

/// Spawn a background task that prints a per-stage breakdown every
/// `FIPS_PERF_INTERVAL_SECS` seconds (default 5). Idempotent — only
/// the first call spawns. No-op when profiling isn't enabled.
pub fn maybe_spawn_reporter() {
    if !enabled() {
        return;
    }
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    let interval = std::env::var("FIPS_PERF_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5)
        .max(1);
    tokio::spawn(async move {
        let mut prev_total = [0u64; N_STAGES];
        let mut prev_count = [0u64; N_STAGES];
        let mut prev_hist = [0u64; N_STAGES * HIST_BUCKETS];
        let mut prev_events = [0u64; N_EVENTS];
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            let mut line = format!("[pipe {}s]", interval);
            for i in 0..N_STAGES {
                let c = COUNT[i].load(Acquire);
                let dc = c.saturating_sub(prev_count[i]);
                if dc == 0 {
                    continue;
                }
                let t = TOTAL_NS[i].load(Relaxed);
                let dt = t.saturating_sub(prev_total[i]);
                prev_total[i] = t;
                prev_count[i] = c;

                let base = i * HIST_BUCKETS;
                let mut hist_delta = [0u64; HIST_BUCKETS];
                for (bucket, delta) in hist_delta.iter_mut().enumerate().take(HIST_BUCKETS) {
                    let idx = base + bucket;
                    let current = HIST[idx].load(Relaxed);
                    *delta = current.saturating_sub(prev_hist[idx]);
                    prev_hist[idx] = current;
                }
                let stage = stage_from_index(i);
                let avg_ns = if dc > 0 { dt / dc } else { 0 };
                let rate_per_sec = fmt_rate_per_sec(dc, interval);
                let p50 = percentile_ns(&hist_delta, dc, 50);
                let p95 = percentile_ns(&hist_delta, dc, 95);
                let p99 = percentile_ns(&hist_delta, dc, 99);
                let approx_max = interval_max_ns(&hist_delta);
                let lifetime_max = MAX_NS[i].load(Relaxed);
                line.push_str(&format!(
                    " {}={}/s avg={} p50<={} p95<={} p99<={} max<={} allmax={}",
                    stage.name(),
                    rate_per_sec,
                    fmt_ns(avg_ns),
                    fmt_ns(p50),
                    fmt_ns(p95),
                    fmt_ns(p99),
                    fmt_ns(approx_max),
                    fmt_ns(lifetime_max),
                ));
            }
            for i in 0..N_EVENTS {
                let current = EVENTS[i].load(Relaxed);
                let delta = current.saturating_sub(prev_events[i]);
                prev_events[i] = current;
                if delta == 0 {
                    continue;
                }
                let event = event_from_index(i);
                let rate_per_sec = fmt_rate_per_sec(delta, interval);
                line.push_str(&format!(
                    " {}={}/s total={}",
                    event.name(),
                    rate_per_sec,
                    current
                ));
            }
            // eprintln so it always lands regardless of RUST_LOG.
            eprintln!("{}", line);
        }
    });
}

fn bucket_for_ns(ns: u64) -> usize {
    if ns <= 1 {
        return 0;
    }
    ((u64::BITS - (ns - 1).leading_zeros()) as usize).min(HIST_BUCKETS - 1)
}

fn bucket_upper_ns(bucket: usize) -> u64 {
    if bucket == 0 {
        1
    } else if bucket >= 63 {
        u64::MAX
    } else {
        1u64 << bucket
    }
}

fn percentile_ns(hist_delta: &[u64; HIST_BUCKETS], total: u64, pct: u64) -> u64 {
    let observed_total = hist_delta.iter().copied().sum::<u64>();
    let total = total.min(observed_total);
    if total == 0 {
        return 0;
    }
    let target = total.saturating_mul(pct).saturating_add(99) / 100;
    let mut seen = 0u64;
    for (idx, count) in hist_delta.iter().enumerate() {
        seen = seen.saturating_add(*count);
        if seen >= target {
            return bucket_upper_ns(idx);
        }
    }
    interval_max_ns(hist_delta)
}

fn interval_max_ns(hist_delta: &[u64; HIST_BUCKETS]) -> u64 {
    for idx in (0..HIST_BUCKETS).rev() {
        if hist_delta[idx] != 0 {
            return bucket_upper_ns(idx);
        }
    }
    0
}

#[cfg(test)]
#[path = "perf_profile/tests.rs"]
mod tests;
