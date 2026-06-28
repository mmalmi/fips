use std::time::Duration;

/// Read-only control queries are status/observability work, not dataplane bulk.
/// Keep their reserved slice tiny so a burst of fipstop/fipsctl reads cannot
/// convoy ahead of packet receive or endpoint/TUN progress.
pub(super) const CONTROL_QUERY_INTERLEAVE_BUDGET: usize = 4;
/// Top-level non-packet queues get shorter turns than raw packet receive.
/// Returning to the biased select loop after a small slice lets ready
/// `packet_rx` preempt bulk fallback, TUN egress, and endpoint command work
/// without adding a second packet-drain path inside those handlers.
pub(super) const NON_PACKET_DRAIN_BUDGET: usize = 16;
/// Raw receive burst cap for pure bulk. Four Linux UDP receive batches keeps
/// high-throughput streams from paying scheduler overhead on every kernel
/// drain.
pub(super) const PACKET_DRAIN_BUDGET: usize = 512;
/// Raw receive burst cap when latency-sensitive packet, TUN, or endpoint work
/// is already waiting. Two Linux UDP receive batches are enough to amortize
/// kernel drains without sitting on the runtime for a long GSO-heavy turn.
pub(super) const LATENCY_PACKET_DRAIN_BUDGET: usize = 256;
pub(super) const RX_LOOP_SLOW_MAINTENANCE_IDLE_TIMEOUT: Duration = Duration::from_millis(100);
pub(super) const RX_LOOP_SLOW_MAINTENANCE_BUSY_TIMEOUT: Duration = Duration::from_millis(10);
pub(super) const RX_LOOP_RECENT_DATA_ACTIVITY_WINDOW: Duration = Duration::from_secs(2);
const RX_LOOP_FAULT_MAX_DELAY_MS: u64 = 5_000;

pub(super) fn non_packet_drain_budget(packet_budget: usize) -> usize {
    packet_budget.min(NON_PACKET_DRAIN_BUDGET)
}

pub(super) fn packet_drain_budget(latency_work_ready: bool) -> usize {
    if latency_work_ready {
        LATENCY_PACKET_DRAIN_BUDGET
    } else {
        PACKET_DRAIN_BUDGET
    }
}

pub(super) fn rx_loop_slow_maintenance_fault_delay() -> Option<Duration> {
    let raw = std::env::var("FIPS_FAULT_INJECT_RX_LOOP_SLOW_MAINTENANCE_MS").ok()?;
    let ms = raw
        .trim()
        .parse::<u64>()
        .ok()?
        .min(RX_LOOP_FAULT_MAX_DELAY_MS);
    (ms > 0).then(|| Duration::from_millis(ms))
}
