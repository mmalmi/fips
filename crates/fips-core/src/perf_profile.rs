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
//!   * `ENDPOINT_SEND_PREPARE` — rx_loop sender-side session/FSP context preparation
//!   * `ENDPOINT_SEND_PLAN` — rx_loop sender-side runtime route/target/reservation planning
//!   * `ENDPOINT_SEND_COMMIT` — rx_loop sender-side bookkeeping commit + worker dispatch
//!   * `FMP_WORKER_FSP_SEAL` — pipelined worker inner FSP AEAD seal
//!   * `FMP_WORKER_FMP_SEAL` — pipelined worker outer FMP AEAD seal
//!   * `FMP_WORKER_DISPATCH` — rx_loop-side worker hashing/admission/channel enqueue
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
//!   * `FMP_WORKER_QUEUE_WAIT` — rx_loop FMP job dispatch → worker
//!   * `FMP_WORKER_PRIORITY_QUEUE_WAIT` — priority FMP encrypt jobs → worker
//!   * `FMP_WORKER_BULK_QUEUE_WAIT` — bulk FMP encrypt jobs → worker
//!   * `DECRYPT_WORKER_QUEUE_WAIT` — rx_loop FMP decrypt job dispatch → decrypt worker
//!   * `DECRYPT_WORKER_PRIORITY_QUEUE_WAIT` — priority FMP decrypt jobs → decrypt worker
//!   * `DECRYPT_WORKER_BULK_QUEUE_WAIT` — bulk FMP decrypt jobs → decrypt worker
//!   * `ENDPOINT_EVENT_WAIT` — rx_loop endpoint delivery → endpoint recv
//!   * `ENDPOINT_PRIORITY_EVENT_WAIT` — priority-sized endpoint events → endpoint recv
//!   * `ENDPOINT_BULK_EVENT_WAIT` — bulk-sized endpoint events → endpoint recv
//!   * `DECRYPT_FALLBACK_WAIT` — plaintext/failure worker completion → rx_loop fallback processing
//!   * `DECRYPT_FALLBACK_PRIORITY_WAIT` — priority plaintext/failure completions → rx_loop
//!   * `DECRYPT_FALLBACK_BULK_WAIT` — bulk plaintext completions → rx_loop
//!   * `DECRYPT_AUTHENTICATED_SESSION_WAIT` — FSP-authenticated worker completion → rx_loop dispatch
//!   * `DECRYPT_AUTHENTICATED_SESSION_PRIORITY_WAIT` — priority FSP-authenticated completions
//!   * `DECRYPT_AUTHENTICATED_SESSION_BULK_WAIT` — bulk FSP-authenticated completions
//!   * `DECRYPT_DIRECT_SESSION_COMMIT_WAIT` — direct worker session commit → rx_loop bookkeeping
//!   * `DECRYPT_DIRECT_SESSION_DATA_WAIT` — direct worker session data → rx_loop delivery
//!   * `DECRYPT_FSP_WORKER_QUEUE_WAIT` — FMP worker → FSP owner-worker handoff
//!   * `DECRYPT_FSP_WORKER_PRIORITY_QUEUE_WAIT` — priority FSP owner-worker handoff
//!   * `DECRYPT_FSP_WORKER_BULK_QUEUE_WAIT` — bulk FSP owner-worker handoff
//!   * `DECRYPT_FSP_WORKER_SERVICE` — FSP owner-worker decrypt/decode/output prep
//!   * `DECRYPT_FSP_WORKER_BULK_INPUT_HEAD_WAIT` — bulk FSP owner enqueue → batch item service start
//!   * `DECRYPT_FSP_WORKER_BULK_INPUT_TAIL_WAIT` — FSP batch item service start → individual job handling
//!   * `DECRYPT_WORKER_BULK_INPUT_HEAD_WAIT` — bulk decrypt-worker enqueue → batch item service start
//!   * `DECRYPT_WORKER_BULK_INPUT_TAIL_WAIT` — decrypt-worker batch item service start → individual job handling
//!   * `DECRYPT_WORKER_BULK_ITEM_SERVICE` — decrypt-worker bulk item service time
//!   * `DECRYPT_WORKER_OUTPUT_FLUSH` — worker output batch flush into rx_loop/endpoint lanes

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
const N_STAGES: usize = 69;
const N_EVENTS: usize = 221;
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
    /// Time spent by the FSP owner worker after queue dequeue preparing the
    /// authenticated output: inner AEAD/replay, inner-header decode, direct
    /// delivery classification, and any batch push/flush work done inline.
    DecryptFspWorkerService = 42,
    /// Bulk FSP owner handoff residence before the worker starts servicing the
    /// dequeued bulk item. This isolates producer/owner backlog from time spent
    /// behind earlier jobs in the same dequeued FSP batch.
    DecryptFspWorkerBulkInputHeadWait = 43,
    /// Bulk FSP owner residence after a dequeued bulk item starts but before an
    /// individual FSP job begins service. This is batch-tail residence inside
    /// one worker turn.
    DecryptFspWorkerBulkInputTailWait = 44,
    ReservedStage45 = 45,
    ReservedStage46 = 46,
    /// Worker-side inner FSP seal for pipelined endpoint sends.
    FmpWorkerFspSeal = 47,
    /// Worker-side outer FMP seal for pipelined endpoint sends.
    FmpWorkerFmpSeal = 48,
    /// Producer-side cost to hash, admit, and enqueue FMP worker jobs.
    FmpWorkerDispatch = 49,
    /// Bulk decrypt-worker residence before the worker starts servicing the
    /// dequeued item. This isolates producer/worker backlog from time spent
    /// behind earlier jobs in one dequeued batch item.
    DecryptWorkerBulkInputHeadWait = 50,
    /// Bulk decrypt-worker residence after a dequeued item starts but before
    /// an individual job begins service.
    DecryptWorkerBulkInputTailWait = 51,
    /// Time a decrypt worker spends servicing one dequeued bulk item.
    DecryptWorkerBulkItemService = 52,
    ReservedStage53 = 53,
    ReservedStage54 = 54,
    ReservedStage55 = 55,
    ReservedStage56 = 56,
    ReservedStage57 = 57,
    ReservedStage58 = 58,
    /// Time spent flushing decrypt-worker output batches into rx_loop fallback
    /// and direct endpoint delivery lanes.
    DecryptWorkerOutputFlush = 59,
    /// Owner-worker service time for an FSP AEAD open completion, including
    /// ordered drain, replay commit, inner-header decode, and output batching.
    FspAeadCompletionService = 60,
    /// Sender rx_loop work to prepare endpoint session data before pipelined
    /// worker admission: FSP context lookup, coordinate warmup decisions, and
    /// inner metadata assembly.
    EndpointSendPrepare = 61,
    /// Sender rx_loop work to turn prepared endpoint data into a worker-ready
    /// dispatch plan: runtime route snapshot use, send-target resolution, and
    /// FSP/FMP counter reservation.
    EndpointSendPlan = 62,
    /// Sender rx_loop work to commit prepared endpoint sends: session/peer
    /// bookkeeping and enqueueing already-admitted worker jobs.
    EndpointSendCommit = 63,
    /// Time spent after a decrypt worker authenticates a plain FMP receive
    /// until the rx loop records link/MMP liveness.
    DecryptAuthenticatedFmpReceiveWait = 64,
    ReservedStage65 = 65,
    ReservedStage66 = 66,
    /// Direct session commit residence before the rx loop applies receive-sync
    /// and session/peer bookkeeping. Recorded in addition to the aggregate
    /// `decrypt_authenticated_session_wait` to keep old bench comparisons intact.
    DecryptDirectSessionCommitWait = 67,
    /// Direct session data residence before the rx loop applies bookkeeping and
    /// delivers payloads through the configured direct sink. Recorded in
    /// addition to the aggregate `decrypt_authenticated_session_wait`.
    DecryptDirectSessionDataWait = 68,
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
            Stage::DecryptFspWorkerService => "decrypt_fsp_worker_service",
            Stage::DecryptFspWorkerBulkInputHeadWait => "decrypt_fsp_worker_bulk_input_head_wait",
            Stage::DecryptFspWorkerBulkInputTailWait => "decrypt_fsp_worker_bulk_input_tail_wait",
            Stage::ReservedStage45 => "reserved_stage_45",
            Stage::ReservedStage46 => "reserved_stage_46",
            Stage::FmpWorkerFspSeal => "fmp_worker_fsp_seal",
            Stage::FmpWorkerFmpSeal => "fmp_worker_fmp_seal",
            Stage::FmpWorkerDispatch => "fmp_worker_dispatch",
            Stage::DecryptWorkerBulkInputHeadWait => "decrypt_worker_bulk_input_head_wait",
            Stage::DecryptWorkerBulkInputTailWait => "decrypt_worker_bulk_input_tail_wait",
            Stage::DecryptWorkerBulkItemService => "decrypt_worker_bulk_item_service",
            Stage::ReservedStage53 => "reserved_stage_53",
            Stage::ReservedStage54 => "reserved_stage_54",
            Stage::ReservedStage55 => "reserved_stage_55",
            Stage::ReservedStage56 => "reserved_stage_56",
            Stage::ReservedStage57 => "reserved_stage_57",
            Stage::ReservedStage58 => "reserved_stage_58",
            Stage::DecryptWorkerOutputFlush => "decrypt_worker_output_flush",
            Stage::FspAeadCompletionService => "fsp_aead_completion_service",
            Stage::EndpointSendPrepare => "endpoint_send_prepare",
            Stage::EndpointSendPlan => "endpoint_send_plan",
            Stage::EndpointSendCommit => "endpoint_send_commit",
            Stage::DecryptAuthenticatedFmpReceiveWait => "decrypt_authenticated_fmp_receive_wait",
            Stage::ReservedStage65 => "reserved_stage_65",
            Stage::ReservedStage66 => "reserved_stage_66",
            Stage::DecryptDirectSessionCommitWait => "decrypt_direct_session_commit_wait",
            Stage::DecryptDirectSessionDataWait => "decrypt_direct_session_data_wait",
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
        42 => Stage::DecryptFspWorkerService,
        43 => Stage::DecryptFspWorkerBulkInputHeadWait,
        44 => Stage::DecryptFspWorkerBulkInputTailWait,
        45 => Stage::ReservedStage45,
        46 => Stage::ReservedStage46,
        47 => Stage::FmpWorkerFspSeal,
        48 => Stage::FmpWorkerFmpSeal,
        49 => Stage::FmpWorkerDispatch,
        50 => Stage::DecryptWorkerBulkInputHeadWait,
        51 => Stage::DecryptWorkerBulkInputTailWait,
        52 => Stage::DecryptWorkerBulkItemService,
        53 => Stage::ReservedStage53,
        54 => Stage::ReservedStage54,
        55 => Stage::ReservedStage55,
        56 => Stage::ReservedStage56,
        57 => Stage::ReservedStage57,
        58 => Stage::ReservedStage58,
        59 => Stage::DecryptWorkerOutputFlush,
        60 => Stage::FspAeadCompletionService,
        61 => Stage::EndpointSendPrepare,
        62 => Stage::EndpointSendPlan,
        63 => Stage::EndpointSendCommit,
        64 => Stage::DecryptAuthenticatedFmpReceiveWait,
        65 => Stage::ReservedStage65,
        66 => Stage::ReservedStage66,
        67 => Stage::DecryptDirectSessionCommitWait,
        68 => Stage::DecryptDirectSessionDataWait,
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
    ReservedEvent3 = 3,
    ReservedEvent4 = 4,
    UdpSendBackpressureSleep = 5,
    ReservedEvent6 = 6,
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
    ReservedEvent20 = 20,
    EndpointEventBacklogHigh = 21,
    EndpointCommandBulkDropped = 22,
    TransportChannelBacklogHigh = 23,
    TransportBulkDropped = 24,
    EndpointEventBulkDropped = 25,
    ReservedEvent26 = 26,
    ReservedEvent27 = 27,
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
    FmpWorkerDispatchBatch = 65,
    FmpWorkerDispatchPackets = 66,
    DecryptWorkerBulkInputWaitGe250us = 67,
    DecryptWorkerBulkInputWaitGe500us = 68,
    DecryptWorkerBulkInputWaitGe1ms = 69,
    DecryptFspOwnerSame = 70,
    DecryptFspOwnerMismatch = 71,
    DecryptFspPathLocal = 72,
    DecryptFspPathHandoff = 73,
    ReservedEvent74 = 74,
    DecryptFspPathFallback = 75,
    ReservedEvent76 = 76,
    ReservedEvent77 = 77,
    ReservedEvent78 = 78,
    ReservedEvent79 = 79,
    FmpWorkerDispatchFlowKeyed = 80,
    FmpWorkerDispatchTargetOnly = 81,
    FmpWorkerDispatchWorker0 = 82,
    FmpWorkerDispatchWorker1 = 83,
    FmpWorkerDispatchWorker2 = 84,
    FmpWorkerDispatchWorker3 = 85,
    FmpWorkerDispatchWorker4 = 86,
    FmpWorkerDispatchWorker5 = 87,
    FmpWorkerDispatchWorker6 = 88,
    FmpWorkerDispatchWorker7 = 89,
    FmpWorkerDispatchWorkerOther = 90,
    ReservedEvent91 = 91,
    ReservedEvent92 = 92,
    ReservedEvent93 = 93,
    ReservedEvent94 = 94,
    ReservedEvent95 = 95,
    FspAeadCompletionReady = 96,
    FspAeadCompletionAccepted = 97,
    FspAeadCompletionAeadFailed = 98,
    FspAeadCompletionReplayDropped = 99,
    FspAeadCompletionReadyMulti = 100,
    ReservedEvent101 = 101,
    ReservedEvent102 = 102,
    ReservedEvent103 = 103,
    ReservedEvent104 = 104,
    ReservedEvent105 = 105,
    ReservedEvent106 = 106,
    ReservedEvent107 = 107,
    LinuxWgBatchChunk = 108,
    LinuxWgBatchChunkPackets = 109,
    LinuxWgBatchChunkFull = 110,
    LinuxWgBatchSenderWaitGe250us = 111,
    LinuxWgBatchSenderWaitGe1ms = 112,
    LinuxWgBatchSenderWaitGe4ms = 113,
    FmpSendGroupSplitTarget = 114,
    FmpSendGroupSplitLane = 115,
    FmpSendGroupSplitBackpressure = 116,
    FmpSendGroupSplitPacketCap = 117,
    ReservedEvent118 = 118,
    ReservedEvent119 = 119,
    ReservedEvent120 = 120,
    ReservedEvent121 = 121,
    FspAeadCompletionStaleSession = 122,
    FspAeadCompletionStaleOrder = 123,
    FspAeadCompletionStaleTicket = 124,
    FspAeadCompletionDuplicateTicket = 125,
    FspAeadCompletionWindowExceeded = 126,
    ReservedEvent127 = 127,
    DecryptWorkerSelectPriority = 128,
    DecryptWorkerSelectFmpCompletion = 129,
    ReservedEvent130 = 130,
    DecryptWorkerSelectBulkPackets = 131,
    DecryptWorkerDrainPriority = 132,
    ReservedEvent133 = 133,
    DecryptWorkerDrainBulkPackets = 134,
    ReservedEvent135 = 135,
    ReservedEvent136 = 136,
    ReservedEvent137 = 137,
    DecryptWorkerControlDropped = 138,
    DecryptWorkerSelectControl = 139,
    DecryptWorkerDrainControl = 140,
    ReservedEvent141 = 141,
    ReservedEvent142 = 142,
    ReservedEvent143 = 143,
    ReservedEvent144 = 144,
    ReservedEvent145 = 145,
    ReservedEvent146 = 146,
    ReservedEvent147 = 147,
    ReservedEvent148 = 148,
    ReservedEvent149 = 149,
    FspAeadCompletionReplayDroppedDuplicate = 150,
    FspAeadCompletionReplayDroppedTooOld = 151,
    FspAeadCompletionReplayDroppedTooOldLagGe2xWindow = 152,
    FspAeadCompletionReplayDroppedTooOldLagGe4xWindow = 153,
    FspAeadCompletionReplayDroppedTooOldLagGe16xWindow = 154,
    FspAeadCompletionReplayDroppedTooOldLagGe64xWindow = 155,
    ReservedEvent156 = 156,
    ReservedEvent157 = 157,
    ReservedEvent158 = 158,
    ReservedEvent159 = 159,
    ReservedEvent160 = 160,
    DecryptAuthenticatedBacklogHigh = 161,
    EndpointEventBulkBacklogHigh = 162,
    PacketBatchPoolFresh = 163,
    PacketBatchPoolReuse = 164,
    PacketBatchPoolReturn = 165,
    PacketBatchPoolDiscard = 166,
    PacketBufferPoolFresh = 167,
    PacketBufferPoolReuse = 168,
    PacketBufferPoolReturn = 169,
    PacketBufferPoolDiscard = 170,
    LinuxBulkUdpPaceWait = 171,
    /// Transport UDP kernel receive drops sampled from the wildcard/listener
    /// UDP transport congestion counter.
    UdpKernelDropped = 172,
    /// Wildcard/listener UDP socket-local receive drops from `SO_RXQ_OVFL`.
    UdpSocketKernelDropped = 173,
    /// Linux namespace-wide UDP `RcvbufErrors` from `/proc/net/snmp`.
    UdpNamespaceRcvbufErrors = 174,
    ReservedEvent175 = 175,
    DecryptFspWorkerReplayDroppedDuplicate = 176,
    DecryptFspWorkerReplayDroppedTooOld = 177,
    DecryptFspWorkerReplayDroppedTooOldLagGe2xWindow = 178,
    DecryptFspWorkerReplayDroppedTooOldLagGe4xWindow = 179,
    DecryptFspWorkerReplayDroppedTooOldLagGe16xWindow = 180,
    DecryptFspWorkerReplayDroppedTooOldLagGe64xWindow = 181,
    DecryptFspPathLocalPriority = 182,
    DecryptFspPathLocalBulk = 183,
    DecryptFspPathHandoffPriority = 184,
    DecryptFspPathHandoffBulk = 185,
    TunWriteBulkDropped = 186,
    TunWriteBulkBacklogHigh = 187,
    DecryptFspPathWorkerOpen = 188,
    DecryptFspPathWorkerOpenBulk = 189,
    DecryptFspOwnerHandoffDropped = 190,
    ReservedEvent191 = 191,
    ReservedEvent192 = 192,
    ReservedEvent193 = 193,
    ReservedEvent194 = 194,
    ReservedEvent195 = 195,
    ReservedEvent196 = 196,
    ReservedEvent197 = 197,
    ReservedEvent198 = 198,
    DecryptFspMalformedDropped = 199,
    FspAeadCompletionAeadFailedLocal = 200,
    ReservedEvent201 = 201,
    ReservedEvent202 = 202,
    ReservedEvent203 = 203,
    ReservedEvent204 = 204,
    FspAeadCompletionEpochMismatch = 205,
    FspAeadCompletionAeadFailedLocalOpen = 206,
    FspAeadCompletionAeadFailedAcceptKbitMismatch = 207,
    ReservedEvent208 = 208,
    ReservedEvent209 = 209,
    ReservedEvent210 = 210,
    DecryptWorkerBatchWorker0 = 211,
    DecryptWorkerBatchWorker1 = 212,
    DecryptWorkerBatchWorker2 = 213,
    DecryptWorkerBatchWorker3 = 214,
    DecryptWorkerBatchWorker4 = 215,
    DecryptWorkerBatchWorker5 = 216,
    DecryptWorkerBatchWorker6 = 217,
    DecryptWorkerBatchWorker7 = 218,
    DecryptWorkerBatchWorkerOther = 219,
    ReservedEvent220 = 220,
}

impl Event {
    const fn name(self) -> &'static str {
        match self {
            Event::UdpSendConnected => "udp_send_connected",
            Event::UdpSendWildcard => "udp_send_wildcard",
            Event::UdpSendBackpressure => "udp_send_backpressure",
            Event::ReservedEvent3 => "reserved_event_3",
            Event::ReservedEvent4 => "reserved_event_4",
            Event::UdpSendBackpressureSleep => "udp_send_backpressure_sleep",
            Event::ReservedEvent6 => "reserved_event_6",
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
            Event::ReservedEvent20 => "reserved_event_20",
            Event::EndpointEventBacklogHigh => "endpoint_event_backlog_high",
            Event::EndpointCommandBulkDropped => "endpoint_command_bulk_dropped",
            Event::TransportChannelBacklogHigh => "transport_channel_backlog_high",
            Event::TransportBulkDropped => "transport_bulk_dropped",
            Event::EndpointEventBulkDropped => "endpoint_event_bulk_dropped",
            Event::ReservedEvent26 => "reserved_event_26",
            Event::ReservedEvent27 => "reserved_event_27",
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
            Event::FmpWorkerDispatchBatch => "fmp_worker_dispatch_batch",
            Event::FmpWorkerDispatchPackets => "fmp_worker_dispatch_packets",
            Event::DecryptWorkerBulkInputWaitGe250us => "decrypt_worker_bulk_input_wait_ge250us",
            Event::DecryptWorkerBulkInputWaitGe500us => "decrypt_worker_bulk_input_wait_ge500us",
            Event::DecryptWorkerBulkInputWaitGe1ms => "decrypt_worker_bulk_input_wait_ge1ms",
            Event::DecryptFspOwnerSame => "decrypt_fsp_owner_same",
            Event::DecryptFspOwnerMismatch => "decrypt_fsp_owner_mismatch",
            Event::DecryptFspPathLocal => "decrypt_fsp_path_local",
            Event::DecryptFspPathHandoff => "decrypt_fsp_path_handoff",
            Event::ReservedEvent74 => "reserved_event_74",
            Event::DecryptFspPathFallback => "decrypt_fsp_path_fallback",
            Event::ReservedEvent76 => "reserved_event_76",
            Event::ReservedEvent77 => "reserved_event_77",
            Event::ReservedEvent78 => "reserved_event_78",
            Event::ReservedEvent79 => "reserved_event_79",
            Event::FmpWorkerDispatchFlowKeyed => "fmp_worker_dispatch_flow_keyed",
            Event::FmpWorkerDispatchTargetOnly => "fmp_worker_dispatch_target_only",
            Event::FmpWorkerDispatchWorker0 => "fmp_worker_dispatch_worker0",
            Event::FmpWorkerDispatchWorker1 => "fmp_worker_dispatch_worker1",
            Event::FmpWorkerDispatchWorker2 => "fmp_worker_dispatch_worker2",
            Event::FmpWorkerDispatchWorker3 => "fmp_worker_dispatch_worker3",
            Event::FmpWorkerDispatchWorker4 => "fmp_worker_dispatch_worker4",
            Event::FmpWorkerDispatchWorker5 => "fmp_worker_dispatch_worker5",
            Event::FmpWorkerDispatchWorker6 => "fmp_worker_dispatch_worker6",
            Event::FmpWorkerDispatchWorker7 => "fmp_worker_dispatch_worker7",
            Event::FmpWorkerDispatchWorkerOther => "fmp_worker_dispatch_worker_other",
            Event::ReservedEvent91 => "reserved_event_91",
            Event::ReservedEvent92 => "reserved_event_92",
            Event::ReservedEvent93 => "reserved_event_93",
            Event::ReservedEvent94 => "reserved_event_94",
            Event::ReservedEvent95 => "reserved_event_95",
            Event::FspAeadCompletionReady => "fsp_aead_completion_ready",
            Event::FspAeadCompletionAccepted => "fsp_aead_completion_accepted",
            Event::FspAeadCompletionAeadFailed => "fsp_aead_completion_aead_failed",
            Event::FspAeadCompletionReplayDropped => "fsp_aead_completion_replay_dropped",
            Event::FspAeadCompletionReadyMulti => "fsp_aead_completion_ready_multi",
            Event::ReservedEvent101 => "reserved_event_101",
            Event::ReservedEvent102 => "reserved_event_102",
            Event::ReservedEvent103 => "reserved_event_103",
            Event::ReservedEvent104 => "reserved_event_104",
            Event::ReservedEvent105 => "reserved_event_105",
            Event::ReservedEvent106 => "reserved_event_106",
            Event::ReservedEvent107 => "reserved_event_107",
            Event::LinuxWgBatchChunk => "linux_wg_batch_chunk",
            Event::LinuxWgBatchChunkPackets => "linux_wg_batch_chunk_packets",
            Event::LinuxWgBatchChunkFull => "linux_wg_batch_chunk_full",
            Event::LinuxWgBatchSenderWaitGe250us => "linux_wg_batch_sender_wait_ge250us",
            Event::LinuxWgBatchSenderWaitGe1ms => "linux_wg_batch_sender_wait_ge1ms",
            Event::LinuxWgBatchSenderWaitGe4ms => "linux_wg_batch_sender_wait_ge4ms",
            Event::FmpSendGroupSplitTarget => "fmp_send_group_split_target",
            Event::FmpSendGroupSplitLane => "fmp_send_group_split_lane",
            Event::FmpSendGroupSplitBackpressure => "fmp_send_group_split_backpressure",
            Event::FmpSendGroupSplitPacketCap => "fmp_send_group_split_packet_cap",
            Event::ReservedEvent118 => "reserved_event_118",
            Event::ReservedEvent119 => "reserved_event_119",
            Event::ReservedEvent120 => "reserved_event_120",
            Event::ReservedEvent121 => "reserved_event_121",
            Event::FspAeadCompletionStaleSession => "fsp_aead_completion_stale_session",
            Event::FspAeadCompletionStaleOrder => "fsp_aead_completion_stale_order",
            Event::FspAeadCompletionStaleTicket => "fsp_aead_completion_stale_ticket",
            Event::FspAeadCompletionDuplicateTicket => "fsp_aead_completion_duplicate_ticket",
            Event::FspAeadCompletionWindowExceeded => "fsp_aead_completion_window_exceeded",
            Event::ReservedEvent127 => "reserved_event_127",
            Event::DecryptWorkerSelectPriority => "decrypt_worker_select_priority",
            Event::DecryptWorkerSelectFmpCompletion => "decrypt_worker_select_fmp_completion",
            Event::ReservedEvent130 => "reserved_event_130",
            Event::DecryptWorkerSelectBulkPackets => "decrypt_worker_select_bulk_packets",
            Event::DecryptWorkerDrainPriority => "decrypt_worker_drain_priority",
            Event::ReservedEvent133 => "reserved_event_133",
            Event::DecryptWorkerDrainBulkPackets => "decrypt_worker_drain_bulk_packets",
            Event::ReservedEvent135 => "reserved_event_135",
            Event::ReservedEvent136 => "reserved_event_136",
            Event::ReservedEvent137 => "reserved_event_137",
            Event::ReservedEvent160 => "reserved_event_160",
            Event::DecryptWorkerControlDropped => "decrypt_worker_control_dropped",
            Event::DecryptWorkerSelectControl => "decrypt_worker_select_control",
            Event::DecryptWorkerDrainControl => "decrypt_worker_drain_control",
            Event::ReservedEvent141 => "reserved_event_141",
            Event::ReservedEvent142 => "reserved_event_142",
            Event::ReservedEvent143 => "reserved_event_143",
            Event::ReservedEvent144 => "reserved_event_144",
            Event::ReservedEvent145 => "reserved_event_145",
            Event::ReservedEvent146 => "reserved_event_146",
            Event::ReservedEvent147 => "reserved_event_147",
            Event::ReservedEvent148 => "reserved_event_148",
            Event::ReservedEvent149 => "reserved_event_149",
            Event::FspAeadCompletionReplayDroppedDuplicate => {
                "fsp_aead_completion_replay_dropped_duplicate"
            }
            Event::FspAeadCompletionReplayDroppedTooOld => {
                "fsp_aead_completion_replay_dropped_too_old"
            }
            Event::FspAeadCompletionReplayDroppedTooOldLagGe2xWindow => {
                "fsp_aead_completion_replay_dropped_too_old_lag_ge_2x_window"
            }
            Event::FspAeadCompletionReplayDroppedTooOldLagGe4xWindow => {
                "fsp_aead_completion_replay_dropped_too_old_lag_ge_4x_window"
            }
            Event::FspAeadCompletionReplayDroppedTooOldLagGe16xWindow => {
                "fsp_aead_completion_replay_dropped_too_old_lag_ge_16x_window"
            }
            Event::FspAeadCompletionReplayDroppedTooOldLagGe64xWindow => {
                "fsp_aead_completion_replay_dropped_too_old_lag_ge_64x_window"
            }
            Event::ReservedEvent156 => "reserved_event_156",
            Event::ReservedEvent157 => "reserved_event_157",
            Event::ReservedEvent158 => "reserved_event_158",
            Event::ReservedEvent159 => "reserved_event_159",
            Event::DecryptAuthenticatedBacklogHigh => "decrypt_authenticated_backlog_high",
            Event::EndpointEventBulkBacklogHigh => "endpoint_event_bulk_backlog_high",
            Event::PacketBatchPoolFresh => "packet_batch_pool_fresh",
            Event::PacketBatchPoolReuse => "packet_batch_pool_reuse",
            Event::PacketBatchPoolReturn => "packet_batch_pool_return",
            Event::PacketBatchPoolDiscard => "packet_batch_pool_discard",
            Event::PacketBufferPoolFresh => "packet_buffer_pool_fresh",
            Event::PacketBufferPoolReuse => "packet_buffer_pool_reuse",
            Event::PacketBufferPoolReturn => "packet_buffer_pool_return",
            Event::PacketBufferPoolDiscard => "packet_buffer_pool_discard",
            Event::LinuxBulkUdpPaceWait => "linux_bulk_udp_pace_wait",
            Event::UdpKernelDropped => "udp_kernel_dropped",
            Event::UdpSocketKernelDropped => "udp_socket_kernel_dropped",
            Event::UdpNamespaceRcvbufErrors => "udp_namespace_rcvbuf_errors",
            Event::ReservedEvent175 => "reserved_event_175",
            Event::DecryptFspWorkerReplayDroppedDuplicate => {
                "decrypt_fsp_worker_replay_dropped_duplicate"
            }
            Event::DecryptFspWorkerReplayDroppedTooOld => {
                "decrypt_fsp_worker_replay_dropped_too_old"
            }
            Event::DecryptFspWorkerReplayDroppedTooOldLagGe2xWindow => {
                "decrypt_fsp_worker_replay_dropped_too_old_lag_ge_2x_window"
            }
            Event::DecryptFspWorkerReplayDroppedTooOldLagGe4xWindow => {
                "decrypt_fsp_worker_replay_dropped_too_old_lag_ge_4x_window"
            }
            Event::DecryptFspWorkerReplayDroppedTooOldLagGe16xWindow => {
                "decrypt_fsp_worker_replay_dropped_too_old_lag_ge_16x_window"
            }
            Event::DecryptFspWorkerReplayDroppedTooOldLagGe64xWindow => {
                "decrypt_fsp_worker_replay_dropped_too_old_lag_ge_64x_window"
            }
            Event::DecryptFspPathLocalPriority => "decrypt_fsp_path_local_priority",
            Event::DecryptFspPathLocalBulk => "decrypt_fsp_path_local_bulk",
            Event::DecryptFspPathHandoffPriority => "decrypt_fsp_path_handoff_priority",
            Event::DecryptFspPathHandoffBulk => "decrypt_fsp_path_handoff_bulk",
            Event::TunWriteBulkDropped => "tun_write_bulk_dropped",
            Event::TunWriteBulkBacklogHigh => "tun_write_bulk_backlog_high",
            Event::DecryptFspPathWorkerOpen => "decrypt_fsp_path_worker_open",
            Event::DecryptFspPathWorkerOpenBulk => "decrypt_fsp_path_worker_open_bulk",
            Event::DecryptFspOwnerHandoffDropped => "decrypt_fsp_owner_handoff_dropped",
            Event::ReservedEvent191 => "reserved_event_191",
            Event::ReservedEvent192 => "reserved_event_192",
            Event::ReservedEvent193 => "reserved_event_193",
            Event::ReservedEvent194 => "reserved_event_194",
            Event::ReservedEvent195 => "reserved_event_195",
            Event::ReservedEvent196 => "reserved_event_196",
            Event::ReservedEvent197 => "reserved_event_197",
            Event::ReservedEvent198 => "reserved_event_198",
            Event::DecryptFspMalformedDropped => "decrypt_fsp_malformed_dropped",
            Event::FspAeadCompletionAeadFailedLocal => "fsp_aead_completion_aead_failed_local",
            Event::ReservedEvent201 => "reserved_event_201",
            Event::ReservedEvent202 => "reserved_event_202",
            Event::ReservedEvent203 => "reserved_event_203",
            Event::ReservedEvent204 => "reserved_event_204",
            Event::FspAeadCompletionEpochMismatch => "fsp_aead_completion_epoch_mismatch",
            Event::FspAeadCompletionAeadFailedLocalOpen => {
                "fsp_aead_completion_aead_failed_local_open"
            }
            Event::FspAeadCompletionAeadFailedAcceptKbitMismatch => {
                "fsp_aead_completion_aead_failed_accept_kbit_mismatch"
            }
            Event::ReservedEvent208 => "reserved_event_208",
            Event::ReservedEvent209 => "reserved_event_209",
            Event::ReservedEvent210 => "reserved_event_210",
            Event::DecryptWorkerBatchWorker0 => "decrypt_worker_batch_worker0",
            Event::DecryptWorkerBatchWorker1 => "decrypt_worker_batch_worker1",
            Event::DecryptWorkerBatchWorker2 => "decrypt_worker_batch_worker2",
            Event::DecryptWorkerBatchWorker3 => "decrypt_worker_batch_worker3",
            Event::DecryptWorkerBatchWorker4 => "decrypt_worker_batch_worker4",
            Event::DecryptWorkerBatchWorker5 => "decrypt_worker_batch_worker5",
            Event::DecryptWorkerBatchWorker6 => "decrypt_worker_batch_worker6",
            Event::DecryptWorkerBatchWorker7 => "decrypt_worker_batch_worker7",
            Event::DecryptWorkerBatchWorkerOther => "decrypt_worker_batch_worker_other",
            Event::ReservedEvent220 => "reserved_event_220",
        }
    }
}

fn event_from_index(idx: usize) -> Event {
    match idx {
        0 => Event::UdpSendConnected,
        1 => Event::UdpSendWildcard,
        2 => Event::UdpSendBackpressure,
        3 => Event::ReservedEvent3,
        4 => Event::ReservedEvent4,
        5 => Event::UdpSendBackpressureSleep,
        6 => Event::ReservedEvent6,
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
        20 => Event::ReservedEvent20,
        21 => Event::EndpointEventBacklogHigh,
        22 => Event::EndpointCommandBulkDropped,
        23 => Event::TransportChannelBacklogHigh,
        24 => Event::TransportBulkDropped,
        25 => Event::EndpointEventBulkDropped,
        26 => Event::ReservedEvent26,
        27 => Event::ReservedEvent27,
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
        65 => Event::FmpWorkerDispatchBatch,
        66 => Event::FmpWorkerDispatchPackets,
        67 => Event::DecryptWorkerBulkInputWaitGe250us,
        68 => Event::DecryptWorkerBulkInputWaitGe500us,
        69 => Event::DecryptWorkerBulkInputWaitGe1ms,
        70 => Event::DecryptFspOwnerSame,
        71 => Event::DecryptFspOwnerMismatch,
        72 => Event::DecryptFspPathLocal,
        73 => Event::DecryptFspPathHandoff,
        74 => Event::ReservedEvent74,
        75 => Event::DecryptFspPathFallback,
        76 => Event::ReservedEvent76,
        77 => Event::ReservedEvent77,
        78 => Event::ReservedEvent78,
        79 => Event::ReservedEvent79,
        80 => Event::FmpWorkerDispatchFlowKeyed,
        81 => Event::FmpWorkerDispatchTargetOnly,
        82 => Event::FmpWorkerDispatchWorker0,
        83 => Event::FmpWorkerDispatchWorker1,
        84 => Event::FmpWorkerDispatchWorker2,
        85 => Event::FmpWorkerDispatchWorker3,
        86 => Event::FmpWorkerDispatchWorker4,
        87 => Event::FmpWorkerDispatchWorker5,
        88 => Event::FmpWorkerDispatchWorker6,
        89 => Event::FmpWorkerDispatchWorker7,
        90 => Event::FmpWorkerDispatchWorkerOther,
        91 => Event::ReservedEvent91,
        92 => Event::ReservedEvent92,
        93 => Event::ReservedEvent93,
        94 => Event::ReservedEvent94,
        95 => Event::ReservedEvent95,
        96 => Event::FspAeadCompletionReady,
        97 => Event::FspAeadCompletionAccepted,
        98 => Event::FspAeadCompletionAeadFailed,
        99 => Event::FspAeadCompletionReplayDropped,
        100 => Event::FspAeadCompletionReadyMulti,
        101 => Event::ReservedEvent101,
        102 => Event::ReservedEvent102,
        103 => Event::ReservedEvent103,
        104 => Event::ReservedEvent104,
        105 => Event::ReservedEvent105,
        106 => Event::ReservedEvent106,
        107 => Event::ReservedEvent107,
        108 => Event::LinuxWgBatchChunk,
        109 => Event::LinuxWgBatchChunkPackets,
        110 => Event::LinuxWgBatchChunkFull,
        111 => Event::LinuxWgBatchSenderWaitGe250us,
        112 => Event::LinuxWgBatchSenderWaitGe1ms,
        113 => Event::LinuxWgBatchSenderWaitGe4ms,
        114 => Event::FmpSendGroupSplitTarget,
        115 => Event::FmpSendGroupSplitLane,
        116 => Event::FmpSendGroupSplitBackpressure,
        117 => Event::FmpSendGroupSplitPacketCap,
        118 => Event::ReservedEvent118,
        119 => Event::ReservedEvent119,
        120 => Event::ReservedEvent120,
        121 => Event::ReservedEvent121,
        122 => Event::FspAeadCompletionStaleSession,
        123 => Event::FspAeadCompletionStaleOrder,
        124 => Event::FspAeadCompletionStaleTicket,
        125 => Event::FspAeadCompletionDuplicateTicket,
        126 => Event::FspAeadCompletionWindowExceeded,
        127 => Event::ReservedEvent127,
        128 => Event::DecryptWorkerSelectPriority,
        129 => Event::DecryptWorkerSelectFmpCompletion,
        130 => Event::ReservedEvent130,
        131 => Event::DecryptWorkerSelectBulkPackets,
        132 => Event::DecryptWorkerDrainPriority,
        133 => Event::ReservedEvent133,
        134 => Event::DecryptWorkerDrainBulkPackets,
        135 => Event::ReservedEvent135,
        136 => Event::ReservedEvent136,
        137 => Event::ReservedEvent137,
        138 => Event::DecryptWorkerControlDropped,
        139 => Event::DecryptWorkerSelectControl,
        140 => Event::DecryptWorkerDrainControl,
        141 => Event::ReservedEvent141,
        142 => Event::ReservedEvent142,
        143 => Event::ReservedEvent143,
        144 => Event::ReservedEvent144,
        145 => Event::ReservedEvent145,
        146 => Event::ReservedEvent146,
        147 => Event::ReservedEvent147,
        148 => Event::ReservedEvent148,
        149 => Event::ReservedEvent149,
        150 => Event::FspAeadCompletionReplayDroppedDuplicate,
        151 => Event::FspAeadCompletionReplayDroppedTooOld,
        152 => Event::FspAeadCompletionReplayDroppedTooOldLagGe2xWindow,
        153 => Event::FspAeadCompletionReplayDroppedTooOldLagGe4xWindow,
        154 => Event::FspAeadCompletionReplayDroppedTooOldLagGe16xWindow,
        155 => Event::FspAeadCompletionReplayDroppedTooOldLagGe64xWindow,
        156 => Event::ReservedEvent156,
        157 => Event::ReservedEvent157,
        158 => Event::ReservedEvent158,
        159 => Event::ReservedEvent159,
        160 => Event::ReservedEvent160,
        161 => Event::DecryptAuthenticatedBacklogHigh,
        162 => Event::EndpointEventBulkBacklogHigh,
        163 => Event::PacketBatchPoolFresh,
        164 => Event::PacketBatchPoolReuse,
        165 => Event::PacketBatchPoolReturn,
        166 => Event::PacketBatchPoolDiscard,
        167 => Event::PacketBufferPoolFresh,
        168 => Event::PacketBufferPoolReuse,
        169 => Event::PacketBufferPoolReturn,
        170 => Event::PacketBufferPoolDiscard,
        171 => Event::LinuxBulkUdpPaceWait,
        172 => Event::UdpKernelDropped,
        173 => Event::UdpSocketKernelDropped,
        174 => Event::UdpNamespaceRcvbufErrors,
        175 => Event::ReservedEvent175,
        176 => Event::DecryptFspWorkerReplayDroppedDuplicate,
        177 => Event::DecryptFspWorkerReplayDroppedTooOld,
        178 => Event::DecryptFspWorkerReplayDroppedTooOldLagGe2xWindow,
        179 => Event::DecryptFspWorkerReplayDroppedTooOldLagGe4xWindow,
        180 => Event::DecryptFspWorkerReplayDroppedTooOldLagGe16xWindow,
        181 => Event::DecryptFspWorkerReplayDroppedTooOldLagGe64xWindow,
        182 => Event::DecryptFspPathLocalPriority,
        183 => Event::DecryptFspPathLocalBulk,
        184 => Event::DecryptFspPathHandoffPriority,
        185 => Event::DecryptFspPathHandoffBulk,
        186 => Event::TunWriteBulkDropped,
        187 => Event::TunWriteBulkBacklogHigh,
        188 => Event::DecryptFspPathWorkerOpen,
        189 => Event::DecryptFspPathWorkerOpenBulk,
        190 => Event::DecryptFspOwnerHandoffDropped,
        191 => Event::ReservedEvent191,
        192 => Event::ReservedEvent192,
        193 => Event::ReservedEvent193,
        194 => Event::ReservedEvent194,
        195 => Event::ReservedEvent195,
        196 => Event::ReservedEvent196,
        197 => Event::ReservedEvent197,
        198 => Event::ReservedEvent198,
        199 => Event::DecryptFspMalformedDropped,
        200 => Event::FspAeadCompletionAeadFailedLocal,
        201 => Event::ReservedEvent201,
        202 => Event::ReservedEvent202,
        203 => Event::ReservedEvent203,
        204 => Event::ReservedEvent204,
        205 => Event::FspAeadCompletionEpochMismatch,
        206 => Event::FspAeadCompletionAeadFailedLocalOpen,
        207 => Event::FspAeadCompletionAeadFailedAcceptKbitMismatch,
        208 => Event::ReservedEvent208,
        209 => Event::ReservedEvent209,
        210 => Event::ReservedEvent210,
        211 => Event::DecryptWorkerBatchWorker0,
        212 => Event::DecryptWorkerBatchWorker1,
        213 => Event::DecryptWorkerBatchWorker2,
        214 => Event::DecryptWorkerBatchWorker3,
        215 => Event::DecryptWorkerBatchWorker4,
        216 => Event::DecryptWorkerBatchWorker5,
        217 => Event::DecryptWorkerBatchWorker6,
        218 => Event::DecryptWorkerBatchWorker7,
        219 => Event::DecryptWorkerBatchWorkerOther,
        220 => Event::ReservedEvent220,
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

/// Record `count` equivalent samples from `start` until now into one stage.
/// No-op when tracing was disabled at the producer or consumer.
#[inline]
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
#[cfg(target_os = "linux")]
pub(crate) fn record_linux_bulk_udp_pace_wait() {
    record_event(Event::LinuxBulkUdpPaceWait);
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
pub(crate) fn record_fmp_send_group_split_target() {
    record_fmp_send_group_split(Event::FmpSendGroupSplitTarget);
}

#[inline]
pub(crate) fn record_fmp_send_group_split_lane() {
    record_fmp_send_group_split(Event::FmpSendGroupSplitLane);
}

#[inline]
pub(crate) fn record_fmp_send_group_split_backpressure() {
    record_fmp_send_group_split(Event::FmpSendGroupSplitBackpressure);
}

#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_fmp_send_group_split_packet_cap() {
    record_fmp_send_group_split(Event::FmpSendGroupSplitPacketCap);
}

#[inline]
fn record_fmp_send_group_split(event: Event) {
    if !enabled() {
        return;
    }
    record_event_count_sample(event, 1);
}

/// Record rx-loop producer-side cost for handing prepared packets to the
/// encrypt worker queues.
///
/// Worker queue residence starts after enqueue. This stage sits before that
/// timestamp and shows whether a hot sender is spending material CPU time in
/// hashing, fair admission, and channel submission before worker ownership.
#[inline]
pub(crate) fn record_fmp_worker_dispatch(elapsed_ns: u64, packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    let packets_u64 = packets as u64;
    let per_packet_ns = elapsed_ns.max(1).saturating_div(packets_u64).max(1);
    record_count_sample(
        Stage::FmpWorkerDispatch,
        per_packet_ns,
        packets_u64,
        bucket_for_ns(per_packet_ns),
    );
    record_event_count_sample(Event::FmpWorkerDispatchBatch, 1);
    record_event_count_sample(Event::FmpWorkerDispatchPackets, packets_u64);
}

#[inline]
pub(crate) fn record_fmp_worker_dispatch_target(worker_idx: usize, flow_keyed: bool) {
    if !enabled() {
        return;
    }
    record_event_count_sample(
        if flow_keyed {
            Event::FmpWorkerDispatchFlowKeyed
        } else {
            Event::FmpWorkerDispatchTargetOnly
        },
        1,
    );
    let worker_event = match worker_idx {
        0 => Event::FmpWorkerDispatchWorker0,
        1 => Event::FmpWorkerDispatchWorker1,
        2 => Event::FmpWorkerDispatchWorker2,
        3 => Event::FmpWorkerDispatchWorker3,
        4 => Event::FmpWorkerDispatchWorker4,
        5 => Event::FmpWorkerDispatchWorker5,
        6 => Event::FmpWorkerDispatchWorker6,
        7 => Event::FmpWorkerDispatchWorker7,
        _ => Event::FmpWorkerDispatchWorkerOther,
    };
    record_event_count_sample(worker_event, 1);
}

/// Record Linux WG-batch worker chunk width before crypto starts.
///
/// This separates producer/container geometry from the final UDP send group
/// shape. Wider chunks can look promising in GSO counters while increasing
/// ordered-sender HOL or burst loss, so keep the input chunk width observable.
#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_linux_wg_batch_chunk(packets: usize, chunk_size: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::LinuxWgBatchChunk, 1);
    record_event_count_sample(Event::LinuxWgBatchChunkPackets, packets as u64);
    if packets >= chunk_size.max(1) {
        record_event_count_sample(Event::LinuxWgBatchChunkFull, 1);
    }
}

/// Record batches whose ordered WG sender had to wait for crypto completion.
///
/// The sender thread intentionally preserves per-flow order. If a wider chunk
/// or worker skew makes the front batch slow, the flow can stall without direct
/// queue drops; threshold counters make that head-of-line wait visible in raw
/// pipeline logs and soak summaries.
#[inline]
#[cfg(target_os = "linux")]
pub(crate) fn record_linux_wg_batch_sender_wait(elapsed_ns: u64) {
    if !enabled() {
        return;
    }
    record_wait_threshold(Event::LinuxWgBatchSenderWaitGe250us, elapsed_ns, 1, 250_000);
    record_wait_threshold(Event::LinuxWgBatchSenderWaitGe1ms, elapsed_ns, 1, 1_000_000);
    record_wait_threshold(Event::LinuxWgBatchSenderWaitGe4ms, elapsed_ns, 1, 4_000_000);
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

#[inline]
pub(crate) fn record_decrypt_worker_batch_target(worker_idx: usize, packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    let worker_event = match worker_idx {
        0 => Event::DecryptWorkerBatchWorker0,
        1 => Event::DecryptWorkerBatchWorker1,
        2 => Event::DecryptWorkerBatchWorker2,
        3 => Event::DecryptWorkerBatchWorker3,
        4 => Event::DecryptWorkerBatchWorker4,
        5 => Event::DecryptWorkerBatchWorker5,
        6 => Event::DecryptWorkerBatchWorker6,
        7 => Event::DecryptWorkerBatchWorker7,
        _ => Event::DecryptWorkerBatchWorkerOther,
    };
    record_event_count_sample(worker_event, packets as u64);
}

#[inline]
pub(crate) fn record_decrypt_worker_select_priority() {
    record_event(Event::DecryptWorkerSelectPriority);
}

#[inline]
pub(crate) fn record_decrypt_worker_select_control() {
    record_event(Event::DecryptWorkerSelectControl);
}

#[inline]
pub(crate) fn record_decrypt_worker_select_bulk(packets: usize) {
    record_event_count(Event::DecryptWorkerSelectBulkPackets, packets as u64);
}

#[inline]
pub(crate) fn record_decrypt_worker_drain_priority() {
    record_event(Event::DecryptWorkerDrainPriority);
}

#[inline]
pub(crate) fn record_decrypt_worker_drain_control() {
    record_event(Event::DecryptWorkerDrainControl);
}

#[inline]
pub(crate) fn record_decrypt_worker_drain_bulk(packets: usize) {
    record_event_count(Event::DecryptWorkerDrainBulkPackets, packets as u64);
}

#[inline]
pub(crate) fn record_fsp_aead_completion_drain(
    ready: usize,
    accepted: usize,
    aead_failures: usize,
    epoch_mismatches: usize,
    replay_drops: usize,
) {
    if !enabled() || ready == 0 {
        return;
    }
    record_event_count_sample(Event::FspAeadCompletionReady, ready as u64);
    if accepted > 0 {
        record_event_count_sample(Event::FspAeadCompletionAccepted, accepted as u64);
    }
    if aead_failures > 0 {
        record_event_count_sample(Event::FspAeadCompletionAeadFailed, aead_failures as u64);
    }
    if epoch_mismatches > 0 {
        record_event_count_sample(
            Event::FspAeadCompletionEpochMismatch,
            epoch_mismatches as u64,
        );
    }
    if replay_drops > 0 {
        record_event_count_sample(Event::FspAeadCompletionReplayDropped, replay_drops as u64);
    }
    if ready > 1 {
        record_event_count_sample(Event::FspAeadCompletionReadyMulti, 1);
    }
}

#[inline]
pub(crate) fn record_fsp_aead_completion_local_aead_failures(local: usize) {
    if !enabled() {
        return;
    }
    if local > 0 {
        record_event_count_sample(Event::FspAeadCompletionAeadFailedLocal, local as u64);
    }
}

#[inline]
pub(crate) fn record_fsp_aead_completion_local_open_aead_failure() {
    record_event(Event::FspAeadCompletionAeadFailedLocalOpen);
}

#[inline]
pub(crate) fn record_fsp_aead_completion_accept_kbit_mismatch() {
    record_event(Event::FspAeadCompletionAeadFailedAcceptKbitMismatch);
}

#[inline]
pub(crate) fn record_fsp_aead_completion_replay_drop_reason(
    reason: crate::noise::ReplayRejection,
    counter_lag: u64,
) {
    if !enabled() {
        return;
    }
    let event = match reason {
        crate::noise::ReplayRejection::Duplicate => Event::FspAeadCompletionReplayDroppedDuplicate,
        crate::noise::ReplayRejection::TooOld => Event::FspAeadCompletionReplayDroppedTooOld,
    };
    record_event(event);
    if reason == crate::noise::ReplayRejection::TooOld {
        record_fsp_aead_completion_too_old_lag_buckets(counter_lag);
    }
}

#[inline]
pub(crate) fn record_decrypt_fsp_worker_replay_drop_reason(
    reason: crate::noise::ReplayRejection,
    counter_lag: u64,
) {
    if !enabled() {
        return;
    }
    let event = match reason {
        crate::noise::ReplayRejection::Duplicate => Event::DecryptFspWorkerReplayDroppedDuplicate,
        crate::noise::ReplayRejection::TooOld => Event::DecryptFspWorkerReplayDroppedTooOld,
    };
    record_event(event);
    if reason == crate::noise::ReplayRejection::TooOld {
        record_decrypt_fsp_worker_too_old_lag_buckets(counter_lag);
    }
}

#[inline]
fn record_fsp_aead_completion_too_old_lag_buckets(counter_lag: u64) {
    let window = crate::noise::REPLAY_WINDOW_SIZE as u64;
    if counter_lag >= window.saturating_mul(2) {
        record_event(Event::FspAeadCompletionReplayDroppedTooOldLagGe2xWindow);
    }
    if counter_lag >= window.saturating_mul(4) {
        record_event(Event::FspAeadCompletionReplayDroppedTooOldLagGe4xWindow);
    }
    if counter_lag >= window.saturating_mul(16) {
        record_event(Event::FspAeadCompletionReplayDroppedTooOldLagGe16xWindow);
    }
    if counter_lag >= window.saturating_mul(64) {
        record_event(Event::FspAeadCompletionReplayDroppedTooOldLagGe64xWindow);
    }
}

#[inline]
fn record_decrypt_fsp_worker_too_old_lag_buckets(counter_lag: u64) {
    let window = crate::noise::REPLAY_WINDOW_SIZE as u64;
    if counter_lag >= window.saturating_mul(2) {
        record_event(Event::DecryptFspWorkerReplayDroppedTooOldLagGe2xWindow);
    }
    if counter_lag >= window.saturating_mul(4) {
        record_event(Event::DecryptFspWorkerReplayDroppedTooOldLagGe4xWindow);
    }
    if counter_lag >= window.saturating_mul(16) {
        record_event(Event::DecryptFspWorkerReplayDroppedTooOldLagGe16xWindow);
    }
    if counter_lag >= window.saturating_mul(64) {
        record_event(Event::DecryptFspWorkerReplayDroppedTooOldLagGe64xWindow);
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
