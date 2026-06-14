//! Runtime perf profiler for the FMP/FSP hot path and queue handoffs.
//!
//! Avoids external dependencies (`perf`, samply, etc.) by instrumenting
//! the key stages directly with `AtomicU64` ns counters, histograms,
//! and packet counts. A background task prints a per-stage breakdown
//! every `FIPS_PERF_INTERVAL_SECS` seconds when `FIPS_PERF=1`,
//! `FIPS_PIPELINE_TRACE=1`, or `NVPN_PIPELINE_TRACE=1` is set at
//! runtime.
//!
//! Enabling adds `Instant::now()` plus a few relaxed atomics per
//! measured stage, so the measured numbers are slightly pessimistic vs
//! production. The relative picture is the point: it shows whether a
//! run is spending time in crypto, syscalls, or scheduler/channel
//! waits.
//!
//! Stages tracked, inbound:
//!   * `UDP_RECV` — recvmmsg syscall + per-message buffer copy
//!   * `FMP_DECRYPT` — outer AEAD open + replay window
//!   * `LINK_DISPATCH` — `dispatch_link_message` excluding FSP work
//!   * `FSP_DECRYPT` — inner AEAD open + replay window
//!   * `TUN_WRITE` — IPv6 shim decompress + tun_tx.send
//!
//! Stages tracked, outbound:
//!   * `FSP_ENCRYPT` — inner AEAD seal (`send_session_data`)
//!   * `FMP_ENCRYPT` — outer AEAD seal (`send_encrypted_link_message`)
//!   * `FMP_WORKER_FSP_SEAL` — pipelined worker inner FSP AEAD seal
//!   * `FMP_WORKER_FMP_SEAL` — pipelined worker outer FMP AEAD seal
//!   * `ENDPOINT_ROUTE_RESOLVE` — batch-level route snapshot selection before
//!     pipelined endpoint send preparation
//!   * `ENDPOINT_SESSION_PREP` — per-packet FSP session context/flags/coords
//!     preparation before worker handoff
//!   * `ENDPOINT_RUNTIME_DISPATCH_PREP` — per-packet runtime route/transport
//!     dispatch and counter reservation before worker job construction
//!   * `ENDPOINT_WORKER_JOB_BUILD` — per-packet wire buffer/header/job
//!     construction before encrypt worker enqueue
//!   * `ENDPOINT_WORKER_COMMIT` — per-packet bookkeeping and encrypt worker
//!     enqueue from prepared endpoint sends
//!   * `ENDPOINT_SEND_BATCH_SERVICE` — batch command handler service time after
//!     command residence ends, counted per payload
//!   * `ENDPOINT_SEND_BATCH_FAST_PATH` — established batch fast-path
//!     prep/commit service, counted per payload
//!   * `ENDPOINT_SEND_BATCH_SLOW_PATH` — fallback batch service, counted per
//!     payload
//!   * `FMP_LINUX_BULK_CONTAINER_SEND` — opt-in Linux ordered bulk-container
//!     sender flush, isolated from global `UDP_SEND`
//!   * `UDP_SEND` — sendmmsg/sendmsg/sendto flush
//!
//! Handoff waits tracked:
//!   * `TRANSPORT_QUEUE_WAIT` — UDP/transport receive loop → rx_loop packet processing
//!   * `TRANSPORT_PRIORITY_QUEUE_WAIT` — priority-sized transport packets → rx_loop packet processing
//!   * `TRANSPORT_BULK_QUEUE_WAIT` — bulk-sized transport packets → rx_loop packet processing
//!   * `TRANSPORT_CHANNEL_WAIT` — UDP/transport receive loop → packet channel dequeue
//!   * `TRANSPORT_PRIORITY_CHANNEL_WAIT` — priority-sized transport packets → packet channel dequeue
//!   * `TRANSPORT_BULK_CHANNEL_WAIT` — bulk-sized transport packets → packet channel dequeue
//!   * `TRANSPORT_RX_LOOP_WAIT` — packet channel dequeue → rx_loop packet processing
//!   * `TRANSPORT_PRIORITY_RX_LOOP_WAIT` — priority-sized packet channel dequeue → rx_loop packet processing
//!   * `TRANSPORT_BULK_RX_LOOP_WAIT` — bulk-sized packet channel dequeue → rx_loop packet processing
//!   * `ENDPOINT_COMMAND_WAIT` — FipsEndpoint send → node command loop
//!   * `ENDPOINT_PRIORITY_COMMAND_WAIT` — priority endpoint command → node command loop
//!   * `ENDPOINT_BULK_COMMAND_WAIT` — bulk endpoint command → node command loop
//!   * `ENDPOINT_COMMAND_ENQUEUE_WAIT` — endpoint command producer waits for
//!     command-channel capacity
//!   * `ENDPOINT_PRIORITY_COMMAND_ENQUEUE_WAIT` — priority endpoint command
//!     producer capacity wait
//!   * `ENDPOINT_BULK_COMMAND_ENQUEUE_WAIT` — bulk endpoint command producer
//!     capacity wait
//!   * `ENDPOINT_COMMAND_DIRECT_PRIORITY_WAIT` — direct priority-select endpoint command wait
//!   * `ENDPOINT_COMMAND_DIRECT_BULK_WAIT` — direct bulk-select endpoint command wait
//!   * `ENDPOINT_COMMAND_SIDE_WAIT` — side-interleaved endpoint command wait
//!   * `ENDPOINT_COMMAND_MAINTENANCE_PRE_WAIT` — pre-maintenance endpoint command wait
//!   * `ENDPOINT_COMMAND_MAINTENANCE_POST_WAIT` — post-maintenance endpoint command wait
//!   * `ENDPOINT_COMMAND_SIDE_PACKET_WAIT` — packet-drain side-interleave endpoint command wait
//!   * `ENDPOINT_COMMAND_SIDE_DECRYPT_PRIORITY_WAIT` — decrypt-priority side-interleave endpoint command wait
//!   * `ENDPOINT_COMMAND_SIDE_AUTHENTICATED_BULK_WAIT` — authenticated-bulk side-interleave endpoint command wait
//!   * `ENDPOINT_COMMAND_SIDE_DECRYPT_BULK_WAIT` — decrypt-bulk side-interleave endpoint command wait
//!   * `FMP_WORKER_QUEUE_WAIT` — rx_loop FMP job dispatch → worker
//!   * `FMP_WORKER_PRIORITY_QUEUE_WAIT` — priority FMP encrypt jobs → worker
//!   * `FMP_WORKER_BULK_QUEUE_WAIT` — bulk FMP encrypt jobs → worker
//!   * `FMP_LINUX_BULK_CONTAINER_QUEUE_WAIT` — Linux ordered bulk container
//!     enqueue → per-flow sender dequeue
//!   * `FMP_LINUX_BULK_CONTAINER_READY_WAIT` — per-flow sender dequeue →
//!     all ordered container slots complete
//!   * `FMP_LINUX_BULK_CONTAINER_FIRST_SLOT_WAIT` — Linux ordered bulk
//!     container enqueue → first worker slot completion
//!   * `FMP_LINUX_BULK_CONTAINER_ALL_SLOTS_WAIT` — Linux ordered bulk
//!     container enqueue → all worker slots complete
//!   * `DECRYPT_WORKER_QUEUE_WAIT` — rx_loop FMP decrypt job dispatch → decrypt worker
//!   * `DECRYPT_WORKER_PRIORITY_QUEUE_WAIT` — priority FMP decrypt jobs → decrypt worker
//!   * `DECRYPT_WORKER_BULK_QUEUE_WAIT` — bulk FMP decrypt jobs → decrypt worker
//!   * `DECRYPT_WORKER_BULK_INPUT_HEAD_WAIT` — bulk decrypt item enqueue →
//!     worker starts servicing the dequeued item, counted per packet
//!   * `DECRYPT_WORKER_BULK_INPUT_TAIL_WAIT` — worker starts servicing a
//!     dequeued bulk item → individual packet handling, counted per packet
//!   * `ENDPOINT_EVENT_WAIT` — rx_loop endpoint delivery → endpoint recv
//!   * `ENDPOINT_PRIORITY_EVENT_WAIT` — priority-sized endpoint events → endpoint recv
//!   * `ENDPOINT_BULK_EVENT_WAIT` — bulk-sized endpoint events → endpoint recv
//!   * `DECRYPT_FALLBACK_WAIT` — plaintext/failure worker completion → rx_loop fallback processing
//!   * `DECRYPT_FALLBACK_PRIORITY_WAIT` — priority plaintext/failure completions → rx_loop
//!   * `DECRYPT_FALLBACK_BULK_WAIT` — bulk plaintext completions → rx_loop
//!   * `DECRYPT_AUTHENTICATED_SESSION_WAIT` — FSP-authenticated worker completion → rx_loop dispatch
//!   * `DECRYPT_AUTHENTICATED_SESSION_PRIORITY_WAIT` — priority FSP-authenticated completions
//!   * `DECRYPT_AUTHENTICATED_SESSION_BULK_WAIT` — bulk FSP-authenticated completions
//!   * `DECRYPT_FSP_WORKER_QUEUE_WAIT` — FMP worker → FSP owner-worker handoff
//!   * `DECRYPT_FSP_WORKER_PRIORITY_QUEUE_WAIT` — priority FSP owner-worker handoff
//!   * `DECRYPT_FSP_WORKER_BULK_QUEUE_WAIT` — bulk FSP owner-worker handoff
//!   * `FMP_AEAD_HELPER_QUEUE_WAIT` — FMP owner-worker helper dispatch → AEAD helper
//!   * `FMP_AEAD_HELPER_COMPLETION_WAIT` — AEAD helper completion → owner-worker
//!   * `FMP_AEAD_HELPER_PRIORITY_COMPLETION_WAIT` — priority helper completion → owner-worker
//!   * `FMP_AEAD_HELPER_BULK_COMPLETION_WAIT` — bulk helper completion → owner-worker
//!   * `FMP_RECEIVE_ORDER_WINDOW_WAIT` — owner-worker waits for ordered FMP
//!     helper completions before issuing more tickets

use std::num::NonZeroU64;
use std::sync::OnceLock;
use std::sync::atomic::{
    AtomicU64,
    Ordering::{Acquire, Relaxed, Release},
};
use std::time::Instant;

mod format;

use format::{fmt_ns, fmt_rate_per_sec};

/// Number of measurement buckets. Indices match `Stage`.
const N_STAGES: usize = 82;
const N_EVENTS: usize = 100;
const HIST_BUCKETS: usize = 48;

/// Stage identifier. `as usize` indexes into the counter arrays.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Stage {
    UdpRecv = 0,
    FmpDecrypt = 1,
    LinkDispatch = 2,
    FspDecrypt = 3,
    TunWrite = 4,
    FspEncrypt = 5,
    FmpEncrypt = 6,
    UdpSend = 7,
    /// Whole `Node::process_packet` body. Anchor for "what fraction of
    /// the receive hot path is in the non-AEAD parts of the pipeline".
    ProcessPacket = 8,
    /// Just the `endpoint_event_tx.send()` for inbound application
    /// payloads — wakes the embedded-endpoint consumer task.
    EndpointDeliver = 9,
    /// Whole `handle_encrypted_session_msg` (FSP receive path) minus
    /// the `FspDecrypt` sub-span. Surfaces dispatch + ipv6_shim +
    /// `Vec::drain` cost on the inner session layer.
    FspHandle = 10,
    /// Whole `handle_endpoint_data_command` body — the SENDER's
    /// per-packet "do everything to push one outbound packet"
    /// dispatch. Compare against the sum of `FspEncrypt`,
    /// `FmpEncrypt`, and `UdpSend` to see how much of the sender
    /// hot path is in state-touching dispatch (sessions/peers
    /// lookups, MMP/stats updates, Vec allocs) vs the AEAD/syscall
    /// work that's a natural fit for an off-task worker.
    EndpointSend = 11,
    /// Time spent waiting after `FipsEndpoint::send`/`blocking_send`
    /// creates a node command until `rx_loop` starts handling it.
    EndpointCommandWait = 12,
    /// Time spent waiting after `rx_loop` creates an FMP encrypt/send
    /// worker job until the worker thread starts encrypting it.
    FmpWorkerQueueWait = 13,
    /// Time spent waiting after a transport receives a packet until
    /// `rx_loop` starts processing it.
    TransportQueueWait = 14,
    /// Time spent waiting after `rx_loop` delivers endpoint data until
    /// the embedded endpoint consumer receives it.
    EndpointEventWait = 15,
    /// Priority-sized transport receive wait, split from the aggregate
    /// `transport_queue_wait` so liveness/control reserve can be verified.
    TransportPriorityQueueWait = 16,
    /// Bulk-sized transport receive wait, split from the aggregate
    /// `transport_queue_wait` so bulk pressure cannot hide priority behavior.
    TransportBulkQueueWait = 17,
    /// Priority-sized endpoint event wait, split from the aggregate
    /// `endpoint_event_wait` so app/control reserve can be verified.
    EndpointPriorityEventWait = 18,
    /// Bulk-sized endpoint event wait, split from the aggregate
    /// `endpoint_event_wait` so bulk pressure cannot hide priority behavior.
    EndpointBulkEventWait = 19,
    /// Time spent after a transport receives a packet until `PacketRx`
    /// dequeues its channel item. This isolates scheduler/channel residence
    /// from per-packet batch-tail residence inside the rx loop.
    TransportChannelWait = 20,
    /// Priority-sized transport channel residence, split from
    /// `transport_channel_wait` so priority reserve stays independently visible.
    TransportPriorityChannelWait = 21,
    /// Bulk-sized transport channel residence, split from
    /// `transport_channel_wait` so bulk pressure stays independently visible.
    TransportBulkChannelWait = 22,
    /// Time spent after a decrypt worker finishes FMP open until the rx loop
    /// starts processing the bounced authenticated plaintext/failure event.
    DecryptFallbackWait = 23,
    /// Priority decrypt completion wait, split from `decrypt_fallback_wait`.
    DecryptFallbackPriorityWait = 24,
    /// Bulk decrypt completion wait, split from `decrypt_fallback_wait`.
    DecryptFallbackBulkWait = 25,
    /// Time spent after `PacketRx` dequeues a transport channel item until the
    /// rx loop starts processing an individual packet from that owned item.
    TransportRxLoopWait = 26,
    /// Priority-sized rx-loop-owned packet residence.
    TransportPriorityRxLoopWait = 27,
    /// Bulk-sized rx-loop-owned packet residence.
    TransportBulkRxLoopWait = 28,
    /// Time spent after the rx loop queues an FMP decrypt job until the decrypt
    /// worker starts handling it.
    DecryptWorkerQueueWait = 29,
    /// Priority decrypt-worker input residence.
    DecryptWorkerPriorityQueueWait = 30,
    /// Bulk decrypt-worker input residence.
    DecryptWorkerBulkQueueWait = 31,
    /// Priority endpoint command residence, split from `endpoint_command_wait`.
    EndpointPriorityCommandWait = 32,
    /// Bulk endpoint command residence, split from `endpoint_command_wait`.
    EndpointBulkCommandWait = 33,
    /// Time spent after a decrypt worker authenticates an established FSP
    /// session frame until the rx loop applies receive-sync and dispatches it.
    DecryptAuthenticatedSessionWait = 34,
    /// Priority authenticated-session completion residence.
    DecryptAuthenticatedSessionPriorityWait = 35,
    /// Bulk authenticated-session completion residence.
    DecryptAuthenticatedSessionBulkWait = 36,
    /// Time spent after an FMP worker queues a local established FSP job to the
    /// FSP owner worker until that worker starts handling it.
    DecryptFspWorkerQueueWait = 37,
    /// Priority FSP owner-worker input residence.
    DecryptFspWorkerPriorityQueueWait = 38,
    /// Bulk FSP owner-worker input residence.
    DecryptFspWorkerBulkQueueWait = 39,
    /// Priority FMP encrypt-worker input residence.
    FmpWorkerPriorityQueueWait = 40,
    /// Bulk FMP encrypt-worker input residence.
    FmpWorkerBulkQueueWait = 41,
    /// Worker-side inner FSP seal for pipelined endpoint sends.
    FmpWorkerFspSeal = 42,
    /// Worker-side outer FMP seal for pipelined endpoint sends.
    FmpWorkerFmpSeal = 43,
    /// Linux bulk-container sender queue residence before the ordered sender
    /// thread starts waiting on the container.
    FmpLinuxBulkContainerQueueWait = 44,
    /// Linux bulk-container sender wait for worker slots to finish sealing.
    FmpLinuxBulkContainerReadyWait = 45,
    /// Batch-level route snapshot selection for established endpoint sends.
    EndpointRouteResolve = 46,
    /// Per-packet FSP context/flags/coords preparation before worker handoff.
    EndpointSessionPrep = 47,
    /// Per-packet runtime route/transport dispatch and counter reservation.
    EndpointRuntimeDispatchPrep = 48,
    /// Per-packet wire buffer/header/job construction before worker enqueue.
    EndpointWorkerJobBuild = 49,
    /// Per-packet bookkeeping and encrypt worker enqueue from prepared sends.
    EndpointWorkerCommit = 50,
    /// Linux bulk-container ordered sender flush after all slots are ready.
    FmpLinuxBulkContainerSend = 51,
    /// Endpoint command residence for the direct priority branch.
    EndpointCommandDirectPriorityWait = 52,
    /// Endpoint command residence for the direct bulk branch.
    EndpointCommandDirectBulkWait = 53,
    /// Endpoint command residence for packet/fallback side interleaves.
    EndpointCommandSideWait = 54,
    /// Endpoint command residence for the bounded drain before maintenance.
    EndpointCommandMaintenancePreWait = 55,
    /// Endpoint command residence for the bounded drain after maintenance.
    EndpointCommandMaintenancePostWait = 56,
    /// Linux bulk-container enqueue until the first worker slot completes.
    FmpLinuxBulkContainerFirstSlotWait = 57,
    /// Linux bulk-container enqueue until every worker slot completes.
    FmpLinuxBulkContainerAllSlotsWait = 58,
    /// Endpoint command producer wait for channel capacity before enqueue.
    EndpointCommandEnqueueWait = 59,
    /// Priority endpoint command producer capacity wait.
    EndpointPriorityCommandEnqueueWait = 60,
    /// Bulk endpoint command producer capacity wait.
    EndpointBulkCommandEnqueueWait = 61,
    /// Endpoint command side-interleave residence from packet-rx drains.
    EndpointCommandSidePacketWait = 62,
    /// Endpoint command side-interleave residence from decrypt-priority drains.
    EndpointCommandSideDecryptPriorityWait = 63,
    /// Endpoint command side-interleave residence from authenticated-bulk drains.
    EndpointCommandSideAuthenticatedBulkWait = 64,
    /// Endpoint command side-interleave residence from decrypt-bulk drains.
    EndpointCommandSideDecryptBulkWait = 65,
    /// Whole batch command handler service time after command residence ends.
    EndpointSendBatchService = 66,
    /// Established endpoint batch fast-path prep/commit service time.
    EndpointSendBatchFastPath = 67,
    /// Fallback endpoint batch service time.
    EndpointSendBatchSlowPath = 68,
    /// FMP AEAD helper job residence before a helper thread starts opening it.
    FmpAeadHelperQueueWait = 69,
    /// FMP AEAD helper completion residence before the owning decrypt worker handles it.
    FmpAeadHelperCompletionWait = 70,
    /// FMP owner-worker residence waiting for ordered helper completions.
    FmpReceiveOrderWindowWait = 71,
    /// Authenticated worker return residence for timestamp-only FMP receives.
    DecryptAuthenticatedFmpReceiveWait = 72,
    /// Authenticated worker return residence for direct-FMP endpoint data.
    DecryptDirectFmpEndpointWait = 73,
    /// Authenticated worker return residence for full FSP session messages.
    DecryptAuthenticatedSessionMessageWait = 74,
    /// Authenticated worker return residence for direct session commit metadata.
    DecryptDirectSessionCommitWait = 75,
    /// Authenticated worker return residence for direct session payloads that
    /// still need rx-loop delivery.
    DecryptDirectSessionDataWait = 76,
    /// Bulk decrypt-worker input residence until a dequeued bulk item starts service.
    DecryptWorkerBulkInputHeadWait = 77,
    /// Per-packet tail inside a dequeued bulk input item before packet handling.
    DecryptWorkerBulkInputTailWait = 78,
    /// Priority FMP AEAD helper completion residence before the owner worker handles it.
    FmpAeadHelperPriorityCompletionWait = 79,
    /// Bulk FMP AEAD helper completion residence before the owner worker handles it.
    FmpAeadHelperBulkCompletionWait = 80,
    /// Dequeued bulk item service time inside the owner decrypt worker.
    DecryptWorkerBulkItemService = 81,
}

impl Stage {
    const fn name(self) -> &'static str {
        match self {
            Stage::UdpRecv => "udp_recv",
            Stage::FmpDecrypt => "fmp_decrypt",
            Stage::LinkDispatch => "link_dispatch",
            Stage::FspDecrypt => "fsp_decrypt",
            Stage::TunWrite => "tun_write",
            Stage::FspEncrypt => "fsp_encrypt",
            Stage::FmpEncrypt => "fmp_encrypt",
            Stage::UdpSend => "udp_send",
            Stage::ProcessPacket => "process_packet",
            Stage::EndpointDeliver => "endpoint_deliver",
            Stage::FspHandle => "fsp_handle",
            Stage::EndpointSend => "endpoint_send",
            Stage::EndpointCommandWait => "endpoint_command_wait",
            Stage::FmpWorkerQueueWait => "fmp_worker_queue_wait",
            Stage::TransportQueueWait => "transport_queue_wait",
            Stage::EndpointEventWait => "endpoint_event_wait",
            Stage::TransportPriorityQueueWait => "transport_priority_queue_wait",
            Stage::TransportBulkQueueWait => "transport_bulk_queue_wait",
            Stage::EndpointPriorityEventWait => "endpoint_priority_event_wait",
            Stage::EndpointBulkEventWait => "endpoint_bulk_event_wait",
            Stage::TransportChannelWait => "transport_channel_wait",
            Stage::TransportPriorityChannelWait => "transport_priority_channel_wait",
            Stage::TransportBulkChannelWait => "transport_bulk_channel_wait",
            Stage::DecryptFallbackWait => "decrypt_fallback_wait",
            Stage::DecryptFallbackPriorityWait => "decrypt_fallback_priority_wait",
            Stage::DecryptFallbackBulkWait => "decrypt_fallback_bulk_wait",
            Stage::TransportRxLoopWait => "transport_rx_loop_wait",
            Stage::TransportPriorityRxLoopWait => "transport_priority_rx_loop_wait",
            Stage::TransportBulkRxLoopWait => "transport_bulk_rx_loop_wait",
            Stage::DecryptWorkerQueueWait => "decrypt_worker_queue_wait",
            Stage::DecryptWorkerPriorityQueueWait => "decrypt_worker_priority_queue_wait",
            Stage::DecryptWorkerBulkQueueWait => "decrypt_worker_bulk_queue_wait",
            Stage::EndpointPriorityCommandWait => "endpoint_priority_command_wait",
            Stage::EndpointBulkCommandWait => "endpoint_bulk_command_wait",
            Stage::DecryptAuthenticatedSessionWait => "decrypt_authenticated_session_wait",
            Stage::DecryptAuthenticatedSessionPriorityWait => {
                "decrypt_authenticated_session_priority_wait"
            }
            Stage::DecryptAuthenticatedSessionBulkWait => "decrypt_authenticated_session_bulk_wait",
            Stage::DecryptFspWorkerQueueWait => "decrypt_fsp_worker_queue_wait",
            Stage::DecryptFspWorkerPriorityQueueWait => "decrypt_fsp_worker_priority_queue_wait",
            Stage::DecryptFspWorkerBulkQueueWait => "decrypt_fsp_worker_bulk_queue_wait",
            Stage::FmpWorkerPriorityQueueWait => "fmp_worker_priority_queue_wait",
            Stage::FmpWorkerBulkQueueWait => "fmp_worker_bulk_queue_wait",
            Stage::FmpWorkerFspSeal => "fmp_worker_fsp_seal",
            Stage::FmpWorkerFmpSeal => "fmp_worker_fmp_seal",
            Stage::FmpLinuxBulkContainerQueueWait => "fmp_linux_bulk_container_queue_wait",
            Stage::FmpLinuxBulkContainerReadyWait => "fmp_linux_bulk_container_ready_wait",
            Stage::EndpointRouteResolve => "endpoint_route_resolve",
            Stage::EndpointSessionPrep => "endpoint_session_prep",
            Stage::EndpointRuntimeDispatchPrep => "endpoint_runtime_dispatch_prep",
            Stage::EndpointWorkerJobBuild => "endpoint_worker_job_build",
            Stage::EndpointWorkerCommit => "endpoint_worker_commit",
            Stage::FmpLinuxBulkContainerSend => "fmp_linux_bulk_container_send",
            Stage::EndpointCommandDirectPriorityWait => "endpoint_command_direct_priority_wait",
            Stage::EndpointCommandDirectBulkWait => "endpoint_command_direct_bulk_wait",
            Stage::EndpointCommandSideWait => "endpoint_command_side_wait",
            Stage::EndpointCommandMaintenancePreWait => "endpoint_command_maintenance_pre_wait",
            Stage::EndpointCommandMaintenancePostWait => "endpoint_command_maintenance_post_wait",
            Stage::FmpLinuxBulkContainerFirstSlotWait => "fmp_linux_bulk_container_first_slot_wait",
            Stage::FmpLinuxBulkContainerAllSlotsWait => "fmp_linux_bulk_container_all_slots_wait",
            Stage::EndpointCommandEnqueueWait => "endpoint_command_enqueue_wait",
            Stage::EndpointPriorityCommandEnqueueWait => "endpoint_priority_command_enqueue_wait",
            Stage::EndpointBulkCommandEnqueueWait => "endpoint_bulk_command_enqueue_wait",
            Stage::EndpointCommandSidePacketWait => "endpoint_command_side_packet_wait",
            Stage::EndpointCommandSideDecryptPriorityWait => {
                "endpoint_command_side_decrypt_priority_wait"
            }
            Stage::EndpointCommandSideAuthenticatedBulkWait => {
                "endpoint_command_side_authenticated_bulk_wait"
            }
            Stage::EndpointCommandSideDecryptBulkWait => "endpoint_command_side_decrypt_bulk_wait",
            Stage::EndpointSendBatchService => "endpoint_send_batch_service",
            Stage::EndpointSendBatchFastPath => "endpoint_send_batch_fast_path",
            Stage::EndpointSendBatchSlowPath => "endpoint_send_batch_slow_path",
            Stage::FmpAeadHelperQueueWait => "fmp_aead_helper_queue_wait",
            Stage::FmpAeadHelperCompletionWait => "fmp_aead_helper_completion_wait",
            Stage::FmpReceiveOrderWindowWait => "fmp_receive_order_window_wait",
            Stage::DecryptAuthenticatedFmpReceiveWait => "decrypt_authenticated_fmp_receive_wait",
            Stage::DecryptDirectFmpEndpointWait => "decrypt_direct_fmp_endpoint_wait",
            Stage::DecryptAuthenticatedSessionMessageWait => {
                "decrypt_authenticated_session_message_wait"
            }
            Stage::DecryptDirectSessionCommitWait => "decrypt_direct_session_commit_wait",
            Stage::DecryptDirectSessionDataWait => "decrypt_direct_session_data_wait",
            Stage::DecryptWorkerBulkInputHeadWait => "decrypt_worker_bulk_input_head_wait",
            Stage::DecryptWorkerBulkInputTailWait => "decrypt_worker_bulk_input_tail_wait",
            Stage::FmpAeadHelperPriorityCompletionWait => {
                "fmp_aead_helper_priority_completion_wait"
            }
            Stage::FmpAeadHelperBulkCompletionWait => "fmp_aead_helper_bulk_completion_wait",
            Stage::DecryptWorkerBulkItemService => "decrypt_worker_bulk_item_service",
        }
    }
}

fn stage_from_index(idx: usize) -> Stage {
    match idx {
        0 => Stage::UdpRecv,
        1 => Stage::FmpDecrypt,
        2 => Stage::LinkDispatch,
        3 => Stage::FspDecrypt,
        4 => Stage::TunWrite,
        5 => Stage::FspEncrypt,
        6 => Stage::FmpEncrypt,
        7 => Stage::UdpSend,
        8 => Stage::ProcessPacket,
        9 => Stage::EndpointDeliver,
        10 => Stage::FspHandle,
        11 => Stage::EndpointSend,
        12 => Stage::EndpointCommandWait,
        13 => Stage::FmpWorkerQueueWait,
        14 => Stage::TransportQueueWait,
        15 => Stage::EndpointEventWait,
        16 => Stage::TransportPriorityQueueWait,
        17 => Stage::TransportBulkQueueWait,
        18 => Stage::EndpointPriorityEventWait,
        19 => Stage::EndpointBulkEventWait,
        20 => Stage::TransportChannelWait,
        21 => Stage::TransportPriorityChannelWait,
        22 => Stage::TransportBulkChannelWait,
        23 => Stage::DecryptFallbackWait,
        24 => Stage::DecryptFallbackPriorityWait,
        25 => Stage::DecryptFallbackBulkWait,
        26 => Stage::TransportRxLoopWait,
        27 => Stage::TransportPriorityRxLoopWait,
        28 => Stage::TransportBulkRxLoopWait,
        29 => Stage::DecryptWorkerQueueWait,
        30 => Stage::DecryptWorkerPriorityQueueWait,
        31 => Stage::DecryptWorkerBulkQueueWait,
        32 => Stage::EndpointPriorityCommandWait,
        33 => Stage::EndpointBulkCommandWait,
        34 => Stage::DecryptAuthenticatedSessionWait,
        35 => Stage::DecryptAuthenticatedSessionPriorityWait,
        36 => Stage::DecryptAuthenticatedSessionBulkWait,
        37 => Stage::DecryptFspWorkerQueueWait,
        38 => Stage::DecryptFspWorkerPriorityQueueWait,
        39 => Stage::DecryptFspWorkerBulkQueueWait,
        40 => Stage::FmpWorkerPriorityQueueWait,
        41 => Stage::FmpWorkerBulkQueueWait,
        42 => Stage::FmpWorkerFspSeal,
        43 => Stage::FmpWorkerFmpSeal,
        44 => Stage::FmpLinuxBulkContainerQueueWait,
        45 => Stage::FmpLinuxBulkContainerReadyWait,
        46 => Stage::EndpointRouteResolve,
        47 => Stage::EndpointSessionPrep,
        48 => Stage::EndpointRuntimeDispatchPrep,
        49 => Stage::EndpointWorkerJobBuild,
        50 => Stage::EndpointWorkerCommit,
        51 => Stage::FmpLinuxBulkContainerSend,
        52 => Stage::EndpointCommandDirectPriorityWait,
        53 => Stage::EndpointCommandDirectBulkWait,
        54 => Stage::EndpointCommandSideWait,
        55 => Stage::EndpointCommandMaintenancePreWait,
        56 => Stage::EndpointCommandMaintenancePostWait,
        57 => Stage::FmpLinuxBulkContainerFirstSlotWait,
        58 => Stage::FmpLinuxBulkContainerAllSlotsWait,
        59 => Stage::EndpointCommandEnqueueWait,
        60 => Stage::EndpointPriorityCommandEnqueueWait,
        61 => Stage::EndpointBulkCommandEnqueueWait,
        62 => Stage::EndpointCommandSidePacketWait,
        63 => Stage::EndpointCommandSideDecryptPriorityWait,
        64 => Stage::EndpointCommandSideAuthenticatedBulkWait,
        65 => Stage::EndpointCommandSideDecryptBulkWait,
        66 => Stage::EndpointSendBatchService,
        67 => Stage::EndpointSendBatchFastPath,
        68 => Stage::EndpointSendBatchSlowPath,
        69 => Stage::FmpAeadHelperQueueWait,
        70 => Stage::FmpAeadHelperCompletionWait,
        71 => Stage::FmpReceiveOrderWindowWait,
        72 => Stage::DecryptAuthenticatedFmpReceiveWait,
        73 => Stage::DecryptDirectFmpEndpointWait,
        74 => Stage::DecryptAuthenticatedSessionMessageWait,
        75 => Stage::DecryptDirectSessionCommitWait,
        76 => Stage::DecryptDirectSessionDataWait,
        77 => Stage::DecryptWorkerBulkInputHeadWait,
        78 => Stage::DecryptWorkerBulkInputTailWait,
        79 => Stage::FmpAeadHelperPriorityCompletionWait,
        80 => Stage::FmpAeadHelperBulkCompletionWait,
        81 => Stage::DecryptWorkerBulkItemService,
        _ => unreachable!(),
    }
}

/// Count-only events that clarify which hot-path variant is active.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Event {
    UdpSendConnected = 0,
    UdpSendWildcard = 1,
    UdpSendBackpressure = 2,
    ConnectedUdpInstalled = 3,
    ConnectedUdpActivationFailed = 4,
    UdpSendBackpressureSleep = 5,
    ConnectedUdpPeerCapSkipped = 6,
    EncryptWorkerQueueFull = 7,
    EncryptWorkerBulkDropped = 8,
    UdpSendBulkDropped = 9,
    DecryptWorkerQueueFull = 10,
    DecryptWorkerBulkDropped = 11,
    DecryptWorkerRegisterFull = 12,
    DecryptWorkerPriorityDropped = 13,
    DecryptFallbackBulkDropped = 14,
    DecryptFallbackPriorityDropped = 15,
    PendingTunDestinationDropped = 16,
    PendingTunPacketDropped = 17,
    PendingEndpointDestinationDropped = 18,
    PendingEndpointPacketDropped = 19,
    ConnectedUdpFdBudgetSkipped = 20,
    EndpointEventBacklogHigh = 21,
    EndpointCommandBulkDropped = 22,
    TransportChannelBacklogHigh = 23,
    TransportBulkDropped = 24,
    EndpointEventBulkDropped = 25,
    ConnectedUdpDirectDecrypt = 26,
    ConnectedUdpDirectDecryptMiss = 27,
    DecryptFallbackBacklogHigh = 28,
    RxLoopSlowMaintenanceTimeout = 29,
    RxLoopSlowMaintenanceSkipped = 30,
    DecryptFallbackPressureDrain = 31,
    DecryptFallbackPriorityGated = 32,
    DecryptFspPriorityQueueFullFallback = 33,
    DecryptFspBulkQueueFullFallback = 34,
    DecryptFspWorkerReplayDropped = 35,
    DecryptAuthenticatedSessionPriorityDropped = 36,
    DecryptAuthenticatedSessionBulkDropped = 37,
    FmpWorkerBatchFlush = 38,
    FmpWorkerBatchPackets = 39,
    FmpWorkerBatchFull = 40,
    FmpWorkerBatchSingle = 41,
    FmpWorkerBatchPriorityPackets = 42,
    FmpWorkerBatchBulkPackets = 43,
    UdpSendGsoBatch = 44,
    UdpSendGsoPackets = 45,
    UdpSendSendmmsgBatch = 46,
    UdpSendSendmmsgPackets = 47,
    DecryptWorkerBatchFlush = 48,
    DecryptWorkerBatchPackets = 49,
    DecryptWorkerBatchFull = 50,
    DecryptWorkerBatchSingle = 51,
    DecryptWorkerBatchPriorityPackets = 52,
    DecryptWorkerBatchBulkPackets = 53,
    UdpSendGsoBatchGe32 = 54,
    UdpSendGsoBatchGe48 = 55,
    UdpSendGsoBatchEq64 = 56,
    UdpSendSendmmsgBatchGe32 = 57,
    UdpSendSendmmsgBatchGe48 = 58,
    UdpSendSendmmsgBatchEq64 = 59,
    FmpSendGroup = 60,
    FmpSendGroupPackets = 61,
    FmpSendGroupSingle = 62,
    EncryptWorkerPriorityQueueFull = 63,
    EncryptWorkerBulkQueueFull = 64,
    FmpLinuxBulkContainerEnqueued = 65,
    FmpLinuxBulkContainerPackets = 66,
    FmpLinuxBulkContainerSkippedPackets = 67,
    FmpLinuxBulkContainerSent = 68,
    FmpLinuxBulkContainerSentPackets = 69,
    FmpLinuxBulkContainerEmpty = 70,
    EndpointSendBatchCommand = 71,
    EndpointSendBatchPackets = 72,
    EndpointSendBatchFull = 73,
    EndpointSendBatchSingle = 74,
    EndpointSendBatchPriorityPackets = 75,
    EndpointSendBatchBulkPackets = 76,
    RxLoopEndpointCommandDrainDirectPriority = 77,
    RxLoopEndpointCommandDrainDirectBulk = 78,
    RxLoopEndpointCommandDrainSide = 79,
    RxLoopEndpointCommandDrainMaintenancePre = 80,
    RxLoopEndpointCommandDrainMaintenancePost = 81,
    RxLoopEndpointCommandDrainSidePacket = 82,
    RxLoopEndpointCommandDrainSideDecryptPriority = 83,
    RxLoopEndpointCommandDrainSideAuthenticatedBulk = 84,
    RxLoopEndpointCommandDrainSideDecryptBulk = 85,
    EncryptWorkerReliableBulkDropped = 86,
    EncryptWorkerDiscardableBulkDropped = 87,
    EndpointDirectFmpBatchFastPath = 88,
    EndpointDirectFmpBatchFastPathPackets = 89,
    EndpointDirectFmpBatchFallback = 90,
    EndpointDirectFmpBatchFallbackPackets = 91,
    EndpointDirectFmpBatchPartial = 92,
    FmpLinuxBulkContainerQueueFull = 93,
    FmpLinuxBulkContainerQueueFullPackets = 94,
    EndpointDirectFmpReceiveDropped = 95,
    EndpointDirectFmpReceiveDroppedPackets = 96,
    DecryptWorkerBulkInputWaitGe250us = 97,
    DecryptWorkerBulkInputWaitGe500us = 98,
    DecryptWorkerBulkInputWaitGe1ms = 99,
}

impl Event {
    const fn name(self) -> &'static str {
        match self {
            Event::UdpSendConnected => "udp_send_connected",
            Event::UdpSendWildcard => "udp_send_wildcard",
            Event::UdpSendBackpressure => "udp_send_backpressure",
            Event::ConnectedUdpInstalled => "connected_udp_installed",
            Event::ConnectedUdpActivationFailed => "connected_udp_activation_failed",
            Event::UdpSendBackpressureSleep => "udp_send_backpressure_sleep",
            Event::ConnectedUdpPeerCapSkipped => "connected_udp_peer_cap_skipped",
            Event::EncryptWorkerQueueFull => "encrypt_worker_queue_full",
            Event::EncryptWorkerBulkDropped => "encrypt_worker_bulk_dropped",
            Event::UdpSendBulkDropped => "udp_send_bulk_dropped",
            Event::DecryptWorkerQueueFull => "decrypt_worker_queue_full",
            Event::DecryptWorkerBulkDropped => "decrypt_worker_bulk_dropped",
            Event::DecryptWorkerRegisterFull => "decrypt_worker_register_full",
            Event::DecryptWorkerPriorityDropped => "decrypt_worker_priority_dropped",
            Event::DecryptFallbackBulkDropped => "decrypt_fallback_bulk_dropped",
            Event::DecryptFallbackPriorityDropped => "decrypt_fallback_priority_dropped",
            Event::PendingTunDestinationDropped => "pending_tun_destination_dropped",
            Event::PendingTunPacketDropped => "pending_tun_packet_dropped",
            Event::PendingEndpointDestinationDropped => "pending_endpoint_destination_dropped",
            Event::PendingEndpointPacketDropped => "pending_endpoint_packet_dropped",
            Event::ConnectedUdpFdBudgetSkipped => "connected_udp_fd_budget_skipped",
            Event::EndpointEventBacklogHigh => "endpoint_event_backlog_high",
            Event::EndpointCommandBulkDropped => "endpoint_command_bulk_dropped",
            Event::TransportChannelBacklogHigh => "transport_channel_backlog_high",
            Event::TransportBulkDropped => "transport_bulk_dropped",
            Event::EndpointEventBulkDropped => "endpoint_event_bulk_dropped",
            Event::ConnectedUdpDirectDecrypt => "connected_udp_direct_decrypt",
            Event::ConnectedUdpDirectDecryptMiss => "connected_udp_direct_decrypt_miss",
            Event::DecryptFallbackBacklogHigh => "decrypt_fallback_backlog_high",
            Event::RxLoopSlowMaintenanceTimeout => "rx_loop_slow_maintenance_timeout",
            Event::RxLoopSlowMaintenanceSkipped => "rx_loop_slow_maintenance_skipped",
            Event::DecryptFallbackPressureDrain => "decrypt_fallback_pressure_drain",
            Event::DecryptFallbackPriorityGated => "decrypt_fallback_priority_gated",
            Event::DecryptFspPriorityQueueFullFallback => {
                "decrypt_fsp_priority_queue_full_fallback"
            }
            Event::DecryptFspBulkQueueFullFallback => "decrypt_fsp_bulk_queue_full_fallback",
            Event::DecryptFspWorkerReplayDropped => "decrypt_fsp_worker_replay_dropped",
            Event::DecryptAuthenticatedSessionPriorityDropped => {
                "decrypt_authenticated_session_priority_dropped"
            }
            Event::DecryptAuthenticatedSessionBulkDropped => {
                "decrypt_authenticated_session_bulk_dropped"
            }
            Event::FmpWorkerBatchFlush => "fmp_worker_batch_flush",
            Event::FmpWorkerBatchPackets => "fmp_worker_batch_packets",
            Event::FmpWorkerBatchFull => "fmp_worker_batch_full",
            Event::FmpWorkerBatchSingle => "fmp_worker_batch_single",
            Event::FmpWorkerBatchPriorityPackets => "fmp_worker_batch_priority_packets",
            Event::FmpWorkerBatchBulkPackets => "fmp_worker_batch_bulk_packets",
            Event::UdpSendGsoBatch => "udp_send_gso_batch",
            Event::UdpSendGsoPackets => "udp_send_gso_packets",
            Event::UdpSendSendmmsgBatch => "udp_send_sendmmsg_batch",
            Event::UdpSendSendmmsgPackets => "udp_send_sendmmsg_packets",
            Event::DecryptWorkerBatchFlush => "decrypt_worker_batch_flush",
            Event::DecryptWorkerBatchPackets => "decrypt_worker_batch_packets",
            Event::DecryptWorkerBatchFull => "decrypt_worker_batch_full",
            Event::DecryptWorkerBatchSingle => "decrypt_worker_batch_single",
            Event::DecryptWorkerBatchPriorityPackets => "decrypt_worker_batch_priority_packets",
            Event::DecryptWorkerBatchBulkPackets => "decrypt_worker_batch_bulk_packets",
            Event::UdpSendGsoBatchGe32 => "udp_send_gso_batch_ge32",
            Event::UdpSendGsoBatchGe48 => "udp_send_gso_batch_ge48",
            Event::UdpSendGsoBatchEq64 => "udp_send_gso_batch_eq64",
            Event::UdpSendSendmmsgBatchGe32 => "udp_send_sendmmsg_batch_ge32",
            Event::UdpSendSendmmsgBatchGe48 => "udp_send_sendmmsg_batch_ge48",
            Event::UdpSendSendmmsgBatchEq64 => "udp_send_sendmmsg_batch_eq64",
            Event::FmpSendGroup => "fmp_send_group",
            Event::FmpSendGroupPackets => "fmp_send_group_packets",
            Event::FmpSendGroupSingle => "fmp_send_group_single",
            Event::EncryptWorkerPriorityQueueFull => "encrypt_worker_priority_queue_full",
            Event::EncryptWorkerBulkQueueFull => "encrypt_worker_bulk_queue_full",
            Event::FmpLinuxBulkContainerEnqueued => "fmp_linux_bulk_container_enqueued",
            Event::FmpLinuxBulkContainerPackets => "fmp_linux_bulk_container_packets",
            Event::FmpLinuxBulkContainerSkippedPackets => {
                "fmp_linux_bulk_container_skipped_packets"
            }
            Event::FmpLinuxBulkContainerSent => "fmp_linux_bulk_container_sent",
            Event::FmpLinuxBulkContainerSentPackets => "fmp_linux_bulk_container_sent_packets",
            Event::FmpLinuxBulkContainerEmpty => "fmp_linux_bulk_container_empty",
            Event::EndpointSendBatchCommand => "endpoint_send_batch_command",
            Event::EndpointSendBatchPackets => "endpoint_send_batch_packets",
            Event::EndpointSendBatchFull => "endpoint_send_batch_full",
            Event::EndpointSendBatchSingle => "endpoint_send_batch_single",
            Event::EndpointSendBatchPriorityPackets => "endpoint_send_batch_priority_packets",
            Event::EndpointSendBatchBulkPackets => "endpoint_send_batch_bulk_packets",
            Event::RxLoopEndpointCommandDrainDirectPriority => {
                "rx_loop_endpoint_command_drain_direct_priority"
            }
            Event::RxLoopEndpointCommandDrainDirectBulk => {
                "rx_loop_endpoint_command_drain_direct_bulk"
            }
            Event::RxLoopEndpointCommandDrainSide => "rx_loop_endpoint_command_drain_side",
            Event::RxLoopEndpointCommandDrainMaintenancePre => {
                "rx_loop_endpoint_command_drain_maintenance_pre"
            }
            Event::RxLoopEndpointCommandDrainMaintenancePost => {
                "rx_loop_endpoint_command_drain_maintenance_post"
            }
            Event::RxLoopEndpointCommandDrainSidePacket => {
                "rx_loop_endpoint_command_drain_side_packet"
            }
            Event::RxLoopEndpointCommandDrainSideDecryptPriority => {
                "rx_loop_endpoint_command_drain_side_decrypt_priority"
            }
            Event::RxLoopEndpointCommandDrainSideAuthenticatedBulk => {
                "rx_loop_endpoint_command_drain_side_authenticated_bulk"
            }
            Event::RxLoopEndpointCommandDrainSideDecryptBulk => {
                "rx_loop_endpoint_command_drain_side_decrypt_bulk"
            }
            Event::EncryptWorkerReliableBulkDropped => "encrypt_worker_reliable_bulk_dropped",
            Event::EncryptWorkerDiscardableBulkDropped => "encrypt_worker_discardable_bulk_dropped",
            Event::EndpointDirectFmpBatchFastPath => "endpoint_direct_fmp_batch_fast_path",
            Event::EndpointDirectFmpBatchFastPathPackets => {
                "endpoint_direct_fmp_batch_fast_path_packets"
            }
            Event::EndpointDirectFmpBatchFallback => "endpoint_direct_fmp_batch_fallback",
            Event::EndpointDirectFmpBatchFallbackPackets => {
                "endpoint_direct_fmp_batch_fallback_packets"
            }
            Event::EndpointDirectFmpBatchPartial => "endpoint_direct_fmp_batch_partial",
            Event::FmpLinuxBulkContainerQueueFull => "fmp_linux_bulk_container_queue_full",
            Event::FmpLinuxBulkContainerQueueFullPackets => {
                "fmp_linux_bulk_container_queue_full_packets"
            }
            Event::EndpointDirectFmpReceiveDropped => "endpoint_direct_fmp_receive_dropped",
            Event::EndpointDirectFmpReceiveDroppedPackets => {
                "endpoint_direct_fmp_receive_dropped_packets"
            }
            Event::DecryptWorkerBulkInputWaitGe250us => "decrypt_worker_bulk_input_wait_ge250us",
            Event::DecryptWorkerBulkInputWaitGe500us => "decrypt_worker_bulk_input_wait_ge500us",
            Event::DecryptWorkerBulkInputWaitGe1ms => "decrypt_worker_bulk_input_wait_ge1ms",
        }
    }
}

fn event_from_index(idx: usize) -> Event {
    match idx {
        0 => Event::UdpSendConnected,
        1 => Event::UdpSendWildcard,
        2 => Event::UdpSendBackpressure,
        3 => Event::ConnectedUdpInstalled,
        4 => Event::ConnectedUdpActivationFailed,
        5 => Event::UdpSendBackpressureSleep,
        6 => Event::ConnectedUdpPeerCapSkipped,
        7 => Event::EncryptWorkerQueueFull,
        8 => Event::EncryptWorkerBulkDropped,
        9 => Event::UdpSendBulkDropped,
        10 => Event::DecryptWorkerQueueFull,
        11 => Event::DecryptWorkerBulkDropped,
        12 => Event::DecryptWorkerRegisterFull,
        13 => Event::DecryptWorkerPriorityDropped,
        14 => Event::DecryptFallbackBulkDropped,
        15 => Event::DecryptFallbackPriorityDropped,
        16 => Event::PendingTunDestinationDropped,
        17 => Event::PendingTunPacketDropped,
        18 => Event::PendingEndpointDestinationDropped,
        19 => Event::PendingEndpointPacketDropped,
        20 => Event::ConnectedUdpFdBudgetSkipped,
        21 => Event::EndpointEventBacklogHigh,
        22 => Event::EndpointCommandBulkDropped,
        23 => Event::TransportChannelBacklogHigh,
        24 => Event::TransportBulkDropped,
        25 => Event::EndpointEventBulkDropped,
        26 => Event::ConnectedUdpDirectDecrypt,
        27 => Event::ConnectedUdpDirectDecryptMiss,
        28 => Event::DecryptFallbackBacklogHigh,
        29 => Event::RxLoopSlowMaintenanceTimeout,
        30 => Event::RxLoopSlowMaintenanceSkipped,
        31 => Event::DecryptFallbackPressureDrain,
        32 => Event::DecryptFallbackPriorityGated,
        33 => Event::DecryptFspPriorityQueueFullFallback,
        34 => Event::DecryptFspBulkQueueFullFallback,
        35 => Event::DecryptFspWorkerReplayDropped,
        36 => Event::DecryptAuthenticatedSessionPriorityDropped,
        37 => Event::DecryptAuthenticatedSessionBulkDropped,
        38 => Event::FmpWorkerBatchFlush,
        39 => Event::FmpWorkerBatchPackets,
        40 => Event::FmpWorkerBatchFull,
        41 => Event::FmpWorkerBatchSingle,
        42 => Event::FmpWorkerBatchPriorityPackets,
        43 => Event::FmpWorkerBatchBulkPackets,
        44 => Event::UdpSendGsoBatch,
        45 => Event::UdpSendGsoPackets,
        46 => Event::UdpSendSendmmsgBatch,
        47 => Event::UdpSendSendmmsgPackets,
        48 => Event::DecryptWorkerBatchFlush,
        49 => Event::DecryptWorkerBatchPackets,
        50 => Event::DecryptWorkerBatchFull,
        51 => Event::DecryptWorkerBatchSingle,
        52 => Event::DecryptWorkerBatchPriorityPackets,
        53 => Event::DecryptWorkerBatchBulkPackets,
        54 => Event::UdpSendGsoBatchGe32,
        55 => Event::UdpSendGsoBatchGe48,
        56 => Event::UdpSendGsoBatchEq64,
        57 => Event::UdpSendSendmmsgBatchGe32,
        58 => Event::UdpSendSendmmsgBatchGe48,
        59 => Event::UdpSendSendmmsgBatchEq64,
        60 => Event::FmpSendGroup,
        61 => Event::FmpSendGroupPackets,
        62 => Event::FmpSendGroupSingle,
        63 => Event::EncryptWorkerPriorityQueueFull,
        64 => Event::EncryptWorkerBulkQueueFull,
        65 => Event::FmpLinuxBulkContainerEnqueued,
        66 => Event::FmpLinuxBulkContainerPackets,
        67 => Event::FmpLinuxBulkContainerSkippedPackets,
        68 => Event::FmpLinuxBulkContainerSent,
        69 => Event::FmpLinuxBulkContainerSentPackets,
        70 => Event::FmpLinuxBulkContainerEmpty,
        71 => Event::EndpointSendBatchCommand,
        72 => Event::EndpointSendBatchPackets,
        73 => Event::EndpointSendBatchFull,
        74 => Event::EndpointSendBatchSingle,
        75 => Event::EndpointSendBatchPriorityPackets,
        76 => Event::EndpointSendBatchBulkPackets,
        77 => Event::RxLoopEndpointCommandDrainDirectPriority,
        78 => Event::RxLoopEndpointCommandDrainDirectBulk,
        79 => Event::RxLoopEndpointCommandDrainSide,
        80 => Event::RxLoopEndpointCommandDrainMaintenancePre,
        81 => Event::RxLoopEndpointCommandDrainMaintenancePost,
        82 => Event::RxLoopEndpointCommandDrainSidePacket,
        83 => Event::RxLoopEndpointCommandDrainSideDecryptPriority,
        84 => Event::RxLoopEndpointCommandDrainSideAuthenticatedBulk,
        85 => Event::RxLoopEndpointCommandDrainSideDecryptBulk,
        86 => Event::EncryptWorkerReliableBulkDropped,
        87 => Event::EncryptWorkerDiscardableBulkDropped,
        88 => Event::EndpointDirectFmpBatchFastPath,
        89 => Event::EndpointDirectFmpBatchFastPathPackets,
        90 => Event::EndpointDirectFmpBatchFallback,
        91 => Event::EndpointDirectFmpBatchFallbackPackets,
        92 => Event::EndpointDirectFmpBatchPartial,
        93 => Event::FmpLinuxBulkContainerQueueFull,
        94 => Event::FmpLinuxBulkContainerQueueFullPackets,
        95 => Event::EndpointDirectFmpReceiveDropped,
        96 => Event::EndpointDirectFmpReceiveDroppedPackets,
        97 => Event::DecryptWorkerBulkInputWaitGe250us,
        98 => Event::DecryptWorkerBulkInputWaitGe500us,
        99 => Event::DecryptWorkerBulkInputWaitGe1ms,
        _ => unreachable!(),
    }
}

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

/// Record `elapsed_ns` for the given stage. No-op when disabled.
pub fn record(stage: Stage, elapsed_ns: u64) {
    record_count(stage, elapsed_ns, 1);
}

/// Record `elapsed_ns` for `count` equivalent stage samples. No-op when disabled.
pub fn record_count(stage: Stage, elapsed_ns: u64, count: u64) {
    if !enabled() {
        return;
    }
    if count == 0 {
        return;
    }
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
    if !enabled() || total_count == 0 {
        return;
    }
    let Some(start) = start else {
        return;
    };
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn record_since_count(stage: Stage, start: Option<TraceStamp>, count: u64) {
    if !enabled() || count == 0 {
        return;
    }
    let Some(start) = start else {
        return;
    };
    let elapsed_ns = start.elapsed_ns().max(1);
    let bucket = bucket_for_ns(elapsed_ns);
    record_count_sample(stage, elapsed_ns, count, bucket);
}

#[inline]
pub(crate) fn record_encrypt_worker_queue_full(priority: bool) {
    record_event(Event::EncryptWorkerQueueFull);
    record_event(if priority {
        Event::EncryptWorkerPriorityQueueFull
    } else {
        Event::EncryptWorkerBulkQueueFull
    });
}

/// Record how much work an FMP encrypt worker drained before one flush.
///
/// These count-only metrics make `fmp_worker_*_queue_wait` easier to interpret:
/// full batches point at a saturated worker/send path, frequent single batches
/// point at wakeup or producer cadence rather than backlog, and lane packet
/// counts show whether a hot turn was bulk-dominated or carrying priority work.
#[inline]
pub(crate) fn record_fmp_worker_batch(
    packets: usize,
    priority_packets: usize,
    bulk_packets: usize,
    max_batch: usize,
) {
    if !enabled() || packets == 0 {
        return;
    }
    debug_assert_eq!(
        packets,
        priority_packets.saturating_add(bulk_packets),
        "FMP worker batch lane counts should cover every packet"
    );
    record_event_count_sample(Event::FmpWorkerBatchFlush, 1);
    record_event_count_sample(Event::FmpWorkerBatchPackets, packets as u64);
    record_event_count_sample(
        Event::FmpWorkerBatchPriorityPackets,
        priority_packets as u64,
    );
    record_event_count_sample(Event::FmpWorkerBatchBulkPackets, bulk_packets as u64);
    if packets >= max_batch.max(1) {
        record_event_count_sample(Event::FmpWorkerBatchFull, 1);
    }
    if packets == 1 {
        record_event_count_sample(Event::FmpWorkerBatchSingle, 1);
    }
}

/// Record how the worker's drained packet batch was split into adjacent
/// send-target groups before Linux GSO/sendmmsg or direct sends.
///
/// This sits between producer batch metrics and UDP syscall batch metrics:
/// if worker batches are wide but selected send groups are tiny, the packet
/// mover is preserving dequeue order across mixed targets/policies rather than
/// handing the kernel one large contiguous flow-shaped group.
#[inline]
pub(crate) fn record_fmp_send_groups(groups: usize, packets: usize, single_groups: usize) {
    if !enabled() || groups == 0 || packets == 0 {
        return;
    }
    debug_assert!(
        single_groups <= groups,
        "single-packet send groups cannot exceed total groups"
    );
    record_event_count_sample(Event::FmpSendGroup, groups as u64);
    record_event_count_sample(Event::FmpSendGroupPackets, packets as u64);
    if single_groups > 0 {
        record_event_count_sample(Event::FmpSendGroupSingle, single_groups as u64);
    }
}

#[inline]
pub(crate) fn record_endpoint_send_batch(
    packets: usize,
    priority_packets: usize,
    bulk_packets: usize,
    max_batch: usize,
) {
    if !enabled() || packets == 0 {
        return;
    }
    debug_assert_eq!(
        packets,
        priority_packets.saturating_add(bulk_packets),
        "endpoint send batch lane counts should cover every packet"
    );
    record_event_count_sample(Event::EndpointSendBatchCommand, 1);
    record_event_count_sample(Event::EndpointSendBatchPackets, packets as u64);
    record_event_count_sample(
        Event::EndpointSendBatchPriorityPackets,
        priority_packets as u64,
    );
    record_event_count_sample(Event::EndpointSendBatchBulkPackets, bulk_packets as u64);
    if packets >= max_batch.max(1) {
        record_event_count_sample(Event::EndpointSendBatchFull, 1);
    }
    if packets == 1 {
        record_event_count_sample(Event::EndpointSendBatchSingle, 1);
    }
}

#[inline]
pub(crate) fn record_endpoint_direct_fmp_batch(fast_path_packets: usize, fallback_packets: usize) {
    if !enabled() || fast_path_packets.saturating_add(fallback_packets) == 0 {
        return;
    }
    if fast_path_packets > 0 {
        record_event_count_sample(Event::EndpointDirectFmpBatchFastPath, 1);
        record_event_count_sample(
            Event::EndpointDirectFmpBatchFastPathPackets,
            fast_path_packets as u64,
        );
    }
    if fallback_packets > 0 {
        record_event_count_sample(Event::EndpointDirectFmpBatchFallback, 1);
        record_event_count_sample(
            Event::EndpointDirectFmpBatchFallbackPackets,
            fallback_packets as u64,
        );
    }
    if fast_path_packets > 0 && fallback_packets > 0 {
        record_event_count_sample(Event::EndpointDirectFmpBatchPartial, 1);
    }
}

#[inline]
pub(crate) fn record_endpoint_direct_fmp_receive_dropped(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::EndpointDirectFmpReceiveDropped, 1);
    record_event_count_sample(
        Event::EndpointDirectFmpReceiveDroppedPackets,
        packets as u64,
    );
}

#[inline]
pub(crate) fn record_decrypt_worker_bulk_input_wait(start: Option<TraceStamp>, count: u64) {
    if !enabled() || count == 0 {
        return;
    }
    let Some(start) = start else {
        return;
    };
    let elapsed_ns = start.elapsed_ns().max(1);
    let bucket = bucket_for_ns(elapsed_ns);
    record_count_sample(
        Stage::DecryptWorkerBulkInputHeadWait,
        elapsed_ns,
        count,
        bucket,
    );
    record_wait_threshold(
        Event::DecryptWorkerBulkInputWaitGe250us,
        elapsed_ns,
        count,
        250_000,
    );
    record_wait_threshold(
        Event::DecryptWorkerBulkInputWaitGe500us,
        elapsed_ns,
        count,
        500_000,
    );
    record_wait_threshold(
        Event::DecryptWorkerBulkInputWaitGe1ms,
        elapsed_ns,
        count,
        1_000_000,
    );
}

#[inline]
fn record_wait_threshold(event: Event, elapsed_ns: u64, count: u64, threshold_ns: u64) {
    if elapsed_ns >= threshold_ns {
        record_event_count_sample(event, count);
    }
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_fmp_linux_bulk_container_enqueued(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::FmpLinuxBulkContainerEnqueued, 1);
    record_event_count_sample(Event::FmpLinuxBulkContainerPackets, packets as u64);
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_fmp_linux_bulk_container_queue_full(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::FmpLinuxBulkContainerQueueFull, 1);
    record_event_count_sample(Event::FmpLinuxBulkContainerQueueFullPackets, packets as u64);
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_fmp_linux_bulk_container_skipped_packet() {
    record_event(Event::FmpLinuxBulkContainerSkippedPackets);
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_fmp_linux_bulk_container_sent(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::FmpLinuxBulkContainerSent, 1);
    record_event_count_sample(Event::FmpLinuxBulkContainerSentPackets, packets as u64);
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_fmp_linux_bulk_container_empty() {
    record_event(Event::FmpLinuxBulkContainerEmpty);
}

/// Record how much packet work a decrypt worker handled before yielding.
///
/// Mirroring the FMP worker batch counters makes `decrypt_worker_*_queue_wait`
/// easier to interpret in stressed runs: full turns imply a saturated worker,
/// single turns point at wakeup/producer cadence, and lane packet counts show
/// whether priority traffic is still getting mixed in under bulk pressure.
#[inline]
pub(crate) fn record_decrypt_worker_batch(
    packets: usize,
    priority_packets: usize,
    bulk_packets: usize,
    max_batch: usize,
) {
    if !enabled() || packets == 0 {
        return;
    }
    debug_assert_eq!(
        packets,
        priority_packets.saturating_add(bulk_packets),
        "decrypt worker batch lane counts should cover every packet"
    );
    record_event_count_sample(Event::DecryptWorkerBatchFlush, 1);
    record_event_count_sample(Event::DecryptWorkerBatchPackets, packets as u64);
    record_event_count_sample(
        Event::DecryptWorkerBatchPriorityPackets,
        priority_packets as u64,
    );
    record_event_count_sample(Event::DecryptWorkerBatchBulkPackets, bulk_packets as u64);
    if packets >= max_batch.max(1) {
        record_event_count_sample(Event::DecryptWorkerBatchFull, 1);
    }
    if packets == 1 {
        record_event_count_sample(Event::DecryptWorkerBatchSingle, 1);
    }
}

/// Record which Linux UDP batch primitive actually submitted packets.
///
/// FMP worker batch metrics expose producer-side fullness; these counters
/// expose whether the send side turned that work into UDP_GSO super-skbs or
/// fell back to plain `sendmmsg(2)` batches.
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

#[inline]
#[cfg(target_os = "linux")]
fn record_udp_send_batch(batch_event: Event, packet_event: Event, packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(batch_event, 1);
    record_event_count_sample(packet_event, packets as u64);
}

#[inline]
#[cfg(target_os = "linux")]
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

#[inline]
#[cfg(target_os = "linux")]
fn udp_send_batch_tail_bucket_flags(packets: usize) -> (bool, bool, bool) {
    (packets >= 32, packets >= 48, packets >= 64)
}

#[inline]
fn record_event_count_sample(event: Event, count: u64) {
    EVENTS[event as usize].fetch_add(count, Relaxed);
}

/// RAII timer — `drop` records the elapsed time into the stage.
/// Use:
/// ```ignore
/// let _t = profile::Timer::start(Stage::FmpDecrypt);
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
            record(self.stage, ns);
        }
    }
}

/// RAII timer for a batch-shaped span that should report per-item cost while
/// preserving the batch's total elapsed time in the aggregate counter.
pub(crate) struct BatchTimer {
    stage: Stage,
    count: u64,
    start: Option<Instant>,
}

impl BatchTimer {
    #[inline]
    pub(crate) fn start(stage: Stage, count: usize) -> Self {
        let count = count as u64;
        let start = if enabled() && count > 0 {
            Some(Instant::now())
        } else {
            None
        };
        Self {
            stage,
            count,
            start,
        }
    }
}

impl Drop for BatchTimer {
    fn drop(&mut self) {
        let Some(t0) = self.start else {
            return;
        };
        if self.count == 0 {
            return;
        }
        let total_ns = t0.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        let per_item_ns = total_ns.saturating_div(self.count).max(1);
        record_count(self.stage, per_item_ns, self.count);
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
mod tests;
