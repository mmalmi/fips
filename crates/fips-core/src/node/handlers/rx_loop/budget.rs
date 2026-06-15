use crate::node::decrypt_worker::DECRYPT_FALLBACK_BACKLOG_HIGH_WATER;
use std::time::Duration;

/// How often the raw-packet drain loop yields a slice of work to the
/// decrypt-fallback drain. Keeps TCP ACK / heartbeat / handshake
/// progress steady under sustained inbound bursts.
pub(super) const FALLBACK_INTERLEAVE_EVERY: usize = 32;
/// Cap on the per-interleave fallback drain so a hot inbound spike
/// can't starve the outer raw-packet drain in the opposite direction.
pub(super) const FALLBACK_INTERLEAVE_BUDGET: usize = 64;
/// Start the pressure drain at the same point where the decrypt fallback lane
/// emits its backlog-high event. The pressure path is gated off whenever raw
/// priority packets are queued.
pub(super) const FALLBACK_PRESSURE_HIGH_WATER: usize = DECRYPT_FALLBACK_BACKLOG_HIGH_WATER;
pub(super) const FALLBACK_PRESSURE_INTERLEAVE_EVERY: usize = 16;
const FALLBACK_PRESSURE_DRAIN_BUDGET: usize = 256;
pub(super) const FALLBACK_PRESSURE_INTERLEAVE_BUDGET: usize = FALLBACK_PRESSURE_DRAIN_BUDGET;
pub(super) const FALLBACK_PRESSURE_TRAILING_BUDGET: usize = FALLBACK_PRESSURE_DRAIN_BUDGET;
/// How often a hot inbound packet drain gives outbound side queues a bounded
/// turn. This keeps TUN egress and endpoint control sends moving when
/// `packet_rx` remains ready for many consecutive biased select iterations.
pub(super) const SIDE_QUEUE_INTERLEAVE_EVERY: usize = 64;
/// Endpoint send commands are already pre-batched before they reach rx_loop.
/// When that mailbox is non-empty, shorten the packet-drain interval so the
/// endpoint producer does not sit for several packet turns before one batch is
/// moved onward to the worker send path.
#[cfg(target_os = "macos")]
pub(super) const SIDE_QUEUE_ENDPOINT_PRESSURE_INTERLEAVE_EVERY: usize = 8;
#[cfg(not(target_os = "macos"))]
pub(super) const SIDE_QUEUE_ENDPOINT_PRESSURE_INTERLEAVE_EVERY: usize = 32;
/// Side-queue interleaves are a progress reserve, not a full drain. Keeping
/// this smaller than the packet budget preserves raw receive throughput while
/// avoiding tick-sized liveness stalls.
pub(super) const SIDE_QUEUE_INTERLEAVE_BUDGET: usize = 64;
/// Top-level non-packet queues get shorter turns than raw packet receive.
/// Returning to the biased select loop after a small slice lets ready
/// `packet_rx` preempt bulk fallback, TUN egress, and endpoint command work
/// without adding a second packet-drain path inside those handlers.
pub(super) const NON_PACKET_DRAIN_BUDGET: usize = 64;
/// Priority decrypt returns carry ACKs, heartbeats, rekeys, and failure
/// reports, so they stay at the top of the biased select. Keep each selected
/// turn well below a raw receive turn so a hot stream of small ACK-shaped
/// returns cannot monopolize the rx-loop ahead of endpoint command progress.
pub(super) const PRIORITY_FALLBACK_DRAIN_BUDGET: usize = NON_PACKET_DRAIN_BUDGET;
/// A directly selected endpoint command has already lost the biased select race
/// to decrypt priority, timer maintenance, authenticated decrypt returns, and
/// raw packet receive. Give that path enough room to dequeue four full endpoint
/// batch commands while still returning within half a raw receive turn.
pub(super) const ENDPOINT_COMMAND_DRAIN_BUDGET: usize = 256;
/// Raw receive burst cap. This amortizes select/scheduler hops across a hot
/// transport queue; fallback/side interleaves reserve progress before the cap.
pub(super) const PACKET_DRAIN_BUDGET: usize = 512;
pub(super) const RX_LOOP_SLOW_MAINTENANCE_IDLE_TIMEOUT: Duration = Duration::from_millis(40);
pub(super) const RX_LOOP_SLOW_MAINTENANCE_BUSY_TIMEOUT: Duration = Duration::from_millis(10);
pub(super) const RX_LOOP_CONNECTED_UDP_IDLE_TIMEOUT: Duration = Duration::from_millis(20);
pub(super) const RX_LOOP_CONNECTED_UDP_BUSY_TIMEOUT: Duration = Duration::from_millis(2);
pub(super) const RX_LOOP_RECENT_DATA_ACTIVITY_WINDOW: Duration = Duration::from_secs(2);
const RX_LOOP_FAULT_MAX_DELAY_MS: u64 = 5_000;

pub(super) fn non_packet_drain_budget(packet_budget: usize) -> usize {
    packet_budget.min(NON_PACKET_DRAIN_BUDGET)
}

pub(super) fn split_side_queue_budget(budget: usize) -> (usize, usize) {
    if budget == 0 {
        return (0, 0);
    }

    let endpoint_budget = (budget / 2).max(1);
    let tun_budget = budget.saturating_sub(endpoint_budget).max(1);
    (endpoint_budget, tun_budget)
}

pub(super) fn remaining_side_queue_budget(budget: usize, drained: usize) -> usize {
    budget.saturating_sub(drained)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FallbackDrainPlan {
    pub(super) interleave_every: usize,
    pub(super) interleave_budget: usize,
    pub(super) trailing_budget: usize,
}

impl FallbackDrainPlan {
    const fn normal() -> Self {
        Self {
            interleave_every: FALLBACK_INTERLEAVE_EVERY,
            interleave_budget: FALLBACK_INTERLEAVE_BUDGET,
            trailing_budget: NON_PACKET_DRAIN_BUDGET,
        }
    }

    const fn pressured() -> Self {
        Self {
            interleave_every: FALLBACK_PRESSURE_INTERLEAVE_EVERY,
            interleave_budget: FALLBACK_PRESSURE_INTERLEAVE_BUDGET,
            trailing_budget: FALLBACK_PRESSURE_TRAILING_BUDGET,
        }
    }
}

pub(super) fn fallback_drain_plan(
    transport_priority_packets: usize,
    decrypt_fallback_bulk_packets: usize,
) -> FallbackDrainPlan {
    if decrypt_fallback_bulk_packets < FALLBACK_PRESSURE_HIGH_WATER {
        return FallbackDrainPlan::normal();
    }

    if transport_priority_packets == 0 {
        crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFallbackPressureDrain);
        FallbackDrainPlan::pressured()
    } else {
        crate::perf_profile::record_event(crate::perf_profile::Event::DecryptFallbackPriorityGated);
        FallbackDrainPlan::normal()
    }
}

pub(super) fn transport_packets_preempt_non_packet(transport_ready_packets: usize) -> bool {
    transport_ready_packets > 0
}

pub(super) fn authenticated_bulk_preempts_packet_rx(transport_ready_packets: usize) -> bool {
    !transport_packets_preempt_non_packet(transport_ready_packets)
}

pub(super) fn endpoint_priority_commands_preempt_packet_rx(
    transport_ready_packets: usize,
    transport_priority_packets: usize,
    already_preempted_transport: bool,
) -> bool {
    transport_priority_packets == 0
        && (!already_preempted_transport || transport_ready_packets == 0)
}

pub(super) fn side_queue_interleave_interval(endpoint_command_ready: bool) -> usize {
    if endpoint_command_ready {
        SIDE_QUEUE_ENDPOINT_PRESSURE_INTERLEAVE_EVERY
    } else {
        SIDE_QUEUE_INTERLEAVE_EVERY
    }
}

pub(super) fn connected_udp_activation_timeout(data_pressure: bool) -> Duration {
    if data_pressure {
        RX_LOOP_CONNECTED_UDP_BUSY_TIMEOUT
    } else {
        RX_LOOP_CONNECTED_UDP_IDLE_TIMEOUT
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
