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
//!   * `FMP_AEAD_HELPER_QUEUE_WAIT` — FMP owner-worker helper dispatch → AEAD helper
//!   * `FMP_AEAD_HELPER_COMPLETION_WAIT` — AEAD helper completion → owner-worker
//!   * `FMP_AEAD_HELPER_PRIORITY_COMPLETION_WAIT` — priority helper completion → owner-worker
//!   * `FMP_AEAD_HELPER_BULK_COMPLETION_WAIT` — bulk helper completion → owner-worker
//!   * `FMP_RECEIVE_ORDER_WINDOW_WAIT` — owner-worker waits for ordered FMP helper completions
//!   * `FMP_AEAD_HELPER_COMPLETION_SERVICE` — owner-worker completion handling + output prep
//!   * `DECRYPT_WORKER_OUTPUT_FLUSH` — worker output batch flush into rx_loop/endpoint lanes
//!   * `FSP_AEAD_WORKER_OPEN_QUEUE_WAIT` — FSP opener-worker bulk queue residence
//!   * `FSP_AEAD_WORKER_OPEN_COMPLETION_WAIT` — FSP opener-worker completion residence
//!   * `CONNECTED_UDP_DRAIN_RECV` — connected peer socket `recvmmsg` drain batch
//!   * `CONNECTED_UDP_DRAIN_RING_WAIT` — connected peer socket drain → userspace dispatch
//!   * `CONNECTED_UDP_FAST_PATH_DISPATCH` — drained connected peer packet dispatch + flush

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
const N_STAGES: usize = 74;
const N_EVENTS: usize = 220;
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
    /// Retired FSP AEAD helper job residence. Kept as a stable historical slot;
    /// current FSP worker-open opens use `FspAeadWorkerOpenQueueWait`.
    FspAeadHelperQueueWait = 45,
    /// Retired FSP AEAD helper completion residence. Kept as a stable historical
    /// slot; current FSP worker-open completions use `FspAeadWorkerOpenCompletionWait`.
    FspAeadHelperCompletionWait = 46,
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
    /// FMP AEAD helper job residence before a helper thread starts opening it.
    FmpAeadHelperQueueWait = 53,
    /// FMP AEAD helper completion residence before the owning decrypt worker handles it.
    FmpAeadHelperCompletionWait = 54,
    /// Priority FMP AEAD helper completion residence before the owner worker handles it.
    FmpAeadHelperPriorityCompletionWait = 55,
    /// Bulk FMP AEAD helper completion residence before the owner worker handles it.
    FmpAeadHelperBulkCompletionWait = 56,
    /// FMP owner-worker residence waiting for ordered helper completions.
    FmpReceiveOrderWindowWait = 57,
    /// Owner-worker service time for an FMP AEAD helper completion, including
    /// ordered drain, ready packet handling, and batching outputs for return.
    FmpAeadHelperCompletionService = 58,
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
    /// Worker-open FSP AEAD job residence before the opener worker starts
    /// opening it. Recorded in addition to the aggregate FSP AEAD queue wait.
    FspAeadWorkerOpenQueueWait = 65,
    /// Worker-open FSP AEAD completion residence before the owner worker
    /// handles it. Recorded in addition to the aggregate FSP AEAD completion wait.
    FspAeadWorkerOpenCompletionWait = 66,
    /// Direct session commit residence before the rx loop applies receive-sync
    /// and session/peer bookkeeping. Recorded in addition to the aggregate
    /// `decrypt_authenticated_session_wait` to keep old bench comparisons intact.
    DecryptDirectSessionCommitWait = 67,
    /// Direct session data residence before the rx loop applies bookkeeping and
    /// delivers payloads through the configured direct sink. Recorded in
    /// addition to the aggregate `decrypt_authenticated_session_wait`.
    DecryptDirectSessionDataWait = 68,
    /// Connected UDP peer-drain socket receive syscall batch time. Separates
    /// kernel drain cadence from userspace dispatch residence.
    ConnectedUdpDrainRecv = 69,
    /// Connected UDP peer-drain userspace dispatch time after packets have
    /// left the kernel: punch filtering, fast-path admission/flush, and
    /// fallback packet-channel handoff.
    ConnectedUdpFastPathDispatch = 70,
    /// Time a drained connected UDP packet spends in the owned userspace ring
    /// before the dispatch thread starts handling it.
    ConnectedUdpDrainRingWait = 71,
    /// Priority-sized connected UDP ring residence, split from the aggregate
    /// ring wait so control/liveness progress stays independently visible.
    ConnectedUdpDrainPriorityRingWait = 72,
    /// Bulk-sized connected UDP ring residence, split from the aggregate ring
    /// wait so bulk burst absorption cannot hide priority behavior.
    ConnectedUdpDrainBulkRingWait = 73,
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
            Stage::FspAeadHelperQueueWait => "fsp_aead_helper_queue_wait",
            Stage::FspAeadHelperCompletionWait => "fsp_aead_helper_completion_wait",
            Stage::FmpWorkerFspSeal => "fmp_worker_fsp_seal",
            Stage::FmpWorkerFmpSeal => "fmp_worker_fmp_seal",
            Stage::FmpWorkerDispatch => "fmp_worker_dispatch",
            Stage::DecryptWorkerBulkInputHeadWait => "decrypt_worker_bulk_input_head_wait",
            Stage::DecryptWorkerBulkInputTailWait => "decrypt_worker_bulk_input_tail_wait",
            Stage::DecryptWorkerBulkItemService => "decrypt_worker_bulk_item_service",
            Stage::FmpAeadHelperQueueWait => "fmp_aead_helper_queue_wait",
            Stage::FmpAeadHelperCompletionWait => "fmp_aead_helper_completion_wait",
            Stage::FmpAeadHelperPriorityCompletionWait => {
                "fmp_aead_helper_priority_completion_wait"
            }
            Stage::FmpAeadHelperBulkCompletionWait => "fmp_aead_helper_bulk_completion_wait",
            Stage::FmpReceiveOrderWindowWait => "fmp_receive_order_window_wait",
            Stage::FmpAeadHelperCompletionService => "fmp_aead_helper_completion_service",
            Stage::DecryptWorkerOutputFlush => "decrypt_worker_output_flush",
            Stage::FspAeadCompletionService => "fsp_aead_completion_service",
            Stage::EndpointSendPrepare => "endpoint_send_prepare",
            Stage::EndpointSendPlan => "endpoint_send_plan",
            Stage::EndpointSendCommit => "endpoint_send_commit",
            Stage::DecryptAuthenticatedFmpReceiveWait => "decrypt_authenticated_fmp_receive_wait",
            Stage::FspAeadWorkerOpenQueueWait => "fsp_aead_worker_open_queue_wait",
            Stage::FspAeadWorkerOpenCompletionWait => "fsp_aead_worker_open_completion_wait",
            Stage::DecryptDirectSessionCommitWait => "decrypt_direct_session_commit_wait",
            Stage::DecryptDirectSessionDataWait => "decrypt_direct_session_data_wait",
            Stage::ConnectedUdpDrainRecv => "connected_udp_drain_recv",
            Stage::ConnectedUdpFastPathDispatch => "connected_udp_fast_path_dispatch",
            Stage::ConnectedUdpDrainRingWait => "connected_udp_drain_ring_wait",
            Stage::ConnectedUdpDrainPriorityRingWait => "connected_udp_drain_priority_ring_wait",
            Stage::ConnectedUdpDrainBulkRingWait => "connected_udp_drain_bulk_ring_wait",
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
        45 => Stage::FspAeadHelperQueueWait,
        46 => Stage::FspAeadHelperCompletionWait,
        47 => Stage::FmpWorkerFspSeal,
        48 => Stage::FmpWorkerFmpSeal,
        49 => Stage::FmpWorkerDispatch,
        50 => Stage::DecryptWorkerBulkInputHeadWait,
        51 => Stage::DecryptWorkerBulkInputTailWait,
        52 => Stage::DecryptWorkerBulkItemService,
        53 => Stage::FmpAeadHelperQueueWait,
        54 => Stage::FmpAeadHelperCompletionWait,
        55 => Stage::FmpAeadHelperPriorityCompletionWait,
        56 => Stage::FmpAeadHelperBulkCompletionWait,
        57 => Stage::FmpReceiveOrderWindowWait,
        58 => Stage::FmpAeadHelperCompletionService,
        59 => Stage::DecryptWorkerOutputFlush,
        60 => Stage::FspAeadCompletionService,
        61 => Stage::EndpointSendPrepare,
        62 => Stage::EndpointSendPlan,
        63 => Stage::EndpointSendCommit,
        64 => Stage::DecryptAuthenticatedFmpReceiveWait,
        65 => Stage::FspAeadWorkerOpenQueueWait,
        66 => Stage::FspAeadWorkerOpenCompletionWait,
        67 => Stage::DecryptDirectSessionCommitWait,
        68 => Stage::DecryptDirectSessionDataWait,
        69 => Stage::ConnectedUdpDrainRecv,
        70 => Stage::ConnectedUdpFastPathDispatch,
        71 => Stage::ConnectedUdpDrainRingWait,
        72 => Stage::ConnectedUdpDrainPriorityRingWait,
        73 => Stage::ConnectedUdpDrainBulkRingWait,
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
    FmpWorkerDispatchBatch = 65,
    FmpWorkerDispatchPackets = 66,
    DecryptWorkerBulkInputWaitGe250us = 67,
    DecryptWorkerBulkInputWaitGe500us = 68,
    DecryptWorkerBulkInputWaitGe1ms = 69,
    DecryptFspOwnerSame = 70,
    DecryptFspOwnerMismatch = 71,
    DecryptFspPathLocal = 72,
    DecryptFspPathHandoff = 73,
    DecryptFspPathHelper = 74,
    DecryptFspPathFallback = 75,
    DecryptFmpPreownerHelper = 76,
    DecryptFmpPreownerHelperFallback = 77,
    DecryptFmpPreownerWindowFallback = 78,
    DecryptFmpPreownerInlineFallback = 79,
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
    FmpAeadCompletionReady = 91,
    FmpAeadCompletionAccepted = 92,
    FmpAeadCompletionAeadFailed = 93,
    FmpAeadCompletionReplayDropped = 94,
    FmpAeadCompletionReadyMulti = 95,
    FspAeadCompletionReady = 96,
    FspAeadCompletionAccepted = 97,
    FspAeadCompletionAeadFailed = 98,
    FspAeadCompletionReplayDropped = 99,
    FspAeadCompletionReadyMulti = 100,
    EndpointBulkFastPathPrepareFailed = 101,
    EndpointBulkFastPathStageFull = 102,
    EndpointBulkFastPathFeedbackFull = 103,
    EndpointBulkFastPathAttempt = 104,
    EndpointBulkFastPathDispatched = 105,
    EndpointBulkFastPathLeaseMiss = 106,
    EndpointBulkFastPathIneligible = 107,
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
    EndpointCommittedBulkDispatchBatch = 118,
    EndpointCommittedBulkDispatchPackets = 119,
    EndpointCommittedBulkDispatchMergedBatch = 120,
    EndpointCommittedBulkDispatchMergedPackets = 121,
    FspAeadCompletionStaleSession = 122,
    FspAeadCompletionStaleOrder = 123,
    FspAeadCompletionStaleTicket = 124,
    FspAeadCompletionDuplicateTicket = 125,
    FspAeadCompletionWindowExceeded = 126,
    DecryptFspOpenWorkerWindowFallback = 127,
    DecryptWorkerSelectPriority = 128,
    DecryptWorkerSelectFmpCompletion = 129,
    DecryptWorkerSelectFspCompletionPackets = 130,
    DecryptWorkerSelectBulkPackets = 131,
    DecryptWorkerDrainPriority = 132,
    DecryptWorkerDrainAeadCompletionPackets = 133,
    DecryptWorkerDrainBulkPackets = 134,
    DecryptWorkerBulkInterleaveAeadCompletionPackets = 135,
    DecryptWorkerBulkInterleaveBudgetExhausted = 136,
    DecryptFspPathWorkerOpen = 137,
    DecryptWorkerControlDropped = 138,
    DecryptWorkerSelectControl = 139,
    DecryptWorkerDrainControl = 140,
    DecryptFspHelperCompletionBacklogFallback = 141,
    DecryptFspHelperQueueFullFallback = 142,
    DecryptFmpHelperCompletionBacklogFallback = 143,
    DecryptFmpPreownerCompletionBacklogFallback = 144,
    DecryptFspOpenWorkerCompletionBacklogFallback = 145,
    FspAeadCompletionReplayDroppedHelper = 146,
    FspAeadCompletionReplayDroppedHelperReturned = 147,
    FspAeadCompletionReplayDroppedWorkerOpen = 148,
    FspAeadCompletionReplayDroppedWorkerOpenReturned = 149,
    FspAeadCompletionReplayDroppedDuplicate = 150,
    FspAeadCompletionReplayDroppedTooOld = 151,
    FspAeadCompletionReplayDroppedTooOldLagGe2xWindow = 152,
    FspAeadCompletionReplayDroppedTooOldLagGe4xWindow = 153,
    FspAeadCompletionReplayDroppedTooOldLagGe16xWindow = 154,
    FspAeadCompletionReplayDroppedTooOldLagGe64xWindow = 155,
    ConnectedUdpDirectDecryptBulkShed = 156,
    DecryptFspOpenPoolQueueFullFallback = 157,
    /// Legacy pipeline name for transport UDP kernel receive drops sampled
    /// once per node tick from SO_RXQ_OVFL-backed transport counters.
    ConnectedUdpKernelDropped = 158,
    /// Per-peer connected UDP socket receive drops sampled directly from
    /// SO_RXQ_OVFL ancillary data on the connected socket drain path.
    ConnectedUdpPeerKernelDropped = 159,
    DecryptFspPathWorkerOpenStriped = 160,
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
    /// Bulk packets drained from a connected UDP socket but shed by the
    /// userspace connected-drain ring before decrypt/dispatch could catch up.
    ConnectedUdpDrainBulkDropped = 175,
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
    DecryptFspPathHelperBulk = 186,
    DecryptFspPathWorkerOpenBulk = 187,
    FspAeadCompletionReturnedHelper = 188,
    FspAeadCompletionReturnedWorkerOpen = 189,
    DecryptFspOwnerHandoffDropped = 190,
    FmpAeadCompletionReplayDroppedPrechecked = 191,
    FmpAeadCompletionReplayDroppedDeferred = 192,
    FmpAeadCompletionReplayDroppedDuplicate = 193,
    FmpAeadCompletionReplayDroppedTooOld = 194,
    FmpAeadCompletionReplayDroppedTooOldLagGe2xWindow = 195,
    FmpAeadCompletionReplayDroppedTooOldLagGe4xWindow = 196,
    FmpAeadCompletionReplayDroppedTooOldLagGe16xWindow = 197,
    FmpAeadCompletionReplayDroppedTooOldLagGe64xWindow = 198,
    DecryptFspMalformedDropped = 199,
    FspAeadCompletionAeadFailedLocal = 200,
    FspAeadCompletionAeadFailedHelper = 201,
    FspAeadCompletionAeadFailedHelperReturned = 202,
    FspAeadCompletionAeadFailedWorkerOpen = 203,
    FspAeadCompletionAeadFailedWorkerOpenReturned = 204,
    FspAeadCompletionEpochMismatch = 205,
    FspAeadCompletionAeadFailedLocalOpen = 206,
    FspAeadCompletionAeadFailedAcceptKbitMismatch = 207,
    DecryptWorkerSelectFspCompletionBatch = 208,
    DecryptWorkerDrainAeadCompletionBatch = 209,
    DecryptWorkerBulkInterleaveAeadCompletionBatch = 210,
    DecryptWorkerBatchWorker0 = 211,
    DecryptWorkerBatchWorker1 = 212,
    DecryptWorkerBatchWorker2 = 213,
    DecryptWorkerBatchWorker3 = 214,
    DecryptWorkerBatchWorker4 = 215,
    DecryptWorkerBatchWorker5 = 216,
    DecryptWorkerBatchWorker6 = 217,
    DecryptWorkerBatchWorker7 = 218,
    DecryptWorkerBatchWorkerOther = 219,
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
            Event::FmpWorkerDispatchBatch => "fmp_worker_dispatch_batch",
            Event::FmpWorkerDispatchPackets => "fmp_worker_dispatch_packets",
            Event::DecryptWorkerBulkInputWaitGe250us => "decrypt_worker_bulk_input_wait_ge250us",
            Event::DecryptWorkerBulkInputWaitGe500us => "decrypt_worker_bulk_input_wait_ge500us",
            Event::DecryptWorkerBulkInputWaitGe1ms => "decrypt_worker_bulk_input_wait_ge1ms",
            Event::DecryptFspOwnerSame => "decrypt_fsp_owner_same",
            Event::DecryptFspOwnerMismatch => "decrypt_fsp_owner_mismatch",
            Event::DecryptFspPathLocal => "decrypt_fsp_path_local",
            Event::DecryptFspPathHandoff => "decrypt_fsp_path_handoff",
            Event::DecryptFspPathHelper => "decrypt_fsp_path_helper",
            Event::DecryptFspPathFallback => "decrypt_fsp_path_fallback",
            Event::DecryptFmpPreownerHelper => "decrypt_fmp_preowner_helper",
            Event::DecryptFmpPreownerHelperFallback => "decrypt_fmp_preowner_helper_fallback",
            Event::DecryptFmpPreownerWindowFallback => "decrypt_fmp_preowner_window_fallback",
            Event::DecryptFmpPreownerInlineFallback => "decrypt_fmp_preowner_inline_fallback",
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
            Event::FmpAeadCompletionReady => "fmp_aead_completion_ready",
            Event::FmpAeadCompletionAccepted => "fmp_aead_completion_accepted",
            Event::FmpAeadCompletionAeadFailed => "fmp_aead_completion_aead_failed",
            Event::FmpAeadCompletionReplayDropped => "fmp_aead_completion_replay_dropped",
            Event::FmpAeadCompletionReadyMulti => "fmp_aead_completion_ready_multi",
            Event::FspAeadCompletionReady => "fsp_aead_completion_ready",
            Event::FspAeadCompletionAccepted => "fsp_aead_completion_accepted",
            Event::FspAeadCompletionAeadFailed => "fsp_aead_completion_aead_failed",
            Event::FspAeadCompletionReplayDropped => "fsp_aead_completion_replay_dropped",
            Event::FspAeadCompletionReadyMulti => "fsp_aead_completion_ready_multi",
            Event::EndpointBulkFastPathPrepareFailed => "endpoint_bulk_fast_path_prepare_failed",
            Event::EndpointBulkFastPathStageFull => "endpoint_bulk_fast_path_stage_full",
            Event::EndpointBulkFastPathFeedbackFull => "endpoint_bulk_fast_path_feedback_full",
            Event::EndpointBulkFastPathAttempt => "endpoint_bulk_fast_path_attempt",
            Event::EndpointBulkFastPathDispatched => "endpoint_bulk_fast_path_dispatched",
            Event::EndpointBulkFastPathLeaseMiss => "endpoint_bulk_fast_path_lease_miss",
            Event::EndpointBulkFastPathIneligible => "endpoint_bulk_fast_path_ineligible",
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
            Event::EndpointCommittedBulkDispatchBatch => "endpoint_committed_bulk_dispatch_batch",
            Event::EndpointCommittedBulkDispatchPackets => {
                "endpoint_committed_bulk_dispatch_packets"
            }
            Event::EndpointCommittedBulkDispatchMergedBatch => {
                "endpoint_committed_bulk_dispatch_merged_batch"
            }
            Event::EndpointCommittedBulkDispatchMergedPackets => {
                "endpoint_committed_bulk_dispatch_merged_packets"
            }
            Event::FspAeadCompletionStaleSession => "fsp_aead_completion_stale_session",
            Event::FspAeadCompletionStaleOrder => "fsp_aead_completion_stale_order",
            Event::FspAeadCompletionStaleTicket => "fsp_aead_completion_stale_ticket",
            Event::FspAeadCompletionDuplicateTicket => "fsp_aead_completion_duplicate_ticket",
            Event::FspAeadCompletionWindowExceeded => "fsp_aead_completion_window_exceeded",
            Event::DecryptFspOpenWorkerWindowFallback => "decrypt_fsp_open_worker_window_fallback",
            Event::DecryptWorkerSelectPriority => "decrypt_worker_select_priority",
            Event::DecryptWorkerSelectFmpCompletion => "decrypt_worker_select_fmp_completion",
            Event::DecryptWorkerSelectFspCompletionPackets => {
                "decrypt_worker_select_fsp_completion_packets"
            }
            Event::DecryptWorkerSelectBulkPackets => "decrypt_worker_select_bulk_packets",
            Event::DecryptWorkerDrainPriority => "decrypt_worker_drain_priority",
            Event::DecryptWorkerDrainAeadCompletionPackets => {
                "decrypt_worker_drain_aead_completion_packets"
            }
            Event::DecryptWorkerDrainBulkPackets => "decrypt_worker_drain_bulk_packets",
            Event::DecryptWorkerBulkInterleaveAeadCompletionPackets => {
                "decrypt_worker_bulk_interleave_aead_completion_packets"
            }
            Event::DecryptWorkerBulkInterleaveBudgetExhausted => {
                "decrypt_worker_bulk_interleave_budget_exhausted"
            }
            Event::DecryptFspPathWorkerOpen => "decrypt_fsp_path_worker_open",
            Event::DecryptFspPathWorkerOpenStriped => "decrypt_fsp_path_worker_open_striped",
            Event::DecryptWorkerControlDropped => "decrypt_worker_control_dropped",
            Event::DecryptWorkerSelectControl => "decrypt_worker_select_control",
            Event::DecryptWorkerDrainControl => "decrypt_worker_drain_control",
            Event::DecryptFspHelperCompletionBacklogFallback => {
                "decrypt_fsp_helper_completion_backlog_fallback"
            }
            Event::DecryptFspHelperQueueFullFallback => "decrypt_fsp_helper_queue_full_fallback",
            Event::DecryptFmpHelperCompletionBacklogFallback => {
                "decrypt_fmp_helper_completion_backlog_fallback"
            }
            Event::DecryptFmpPreownerCompletionBacklogFallback => {
                "decrypt_fmp_preowner_completion_backlog_fallback"
            }
            Event::DecryptFspOpenWorkerCompletionBacklogFallback => {
                "decrypt_fsp_open_worker_completion_backlog_fallback"
            }
            Event::FspAeadCompletionReplayDroppedHelper => {
                "fsp_aead_completion_replay_dropped_helper"
            }
            Event::FspAeadCompletionReplayDroppedHelperReturned => {
                "fsp_aead_completion_replay_dropped_helper_returned"
            }
            Event::FspAeadCompletionReplayDroppedWorkerOpen => {
                "fsp_aead_completion_replay_dropped_worker_open"
            }
            Event::FspAeadCompletionReplayDroppedWorkerOpenReturned => {
                "fsp_aead_completion_replay_dropped_worker_open_returned"
            }
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
            Event::ConnectedUdpDirectDecryptBulkShed => "connected_udp_direct_decrypt_bulk_shed",
            Event::DecryptFspOpenPoolQueueFullFallback => {
                "decrypt_fsp_open_pool_queue_full_fallback"
            }
            Event::ConnectedUdpKernelDropped => "connected_udp_kernel_dropped",
            Event::ConnectedUdpPeerKernelDropped => "connected_udp_peer_kernel_dropped",
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
            Event::ConnectedUdpDrainBulkDropped => "connected_udp_drain_bulk_dropped",
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
            Event::DecryptFspPathHelperBulk => "decrypt_fsp_path_helper_bulk",
            Event::DecryptFspPathWorkerOpenBulk => "decrypt_fsp_path_worker_open_bulk",
            Event::FspAeadCompletionReturnedHelper => "fsp_aead_completion_returned_helper",
            Event::FspAeadCompletionReturnedWorkerOpen => {
                "fsp_aead_completion_returned_worker_open"
            }
            Event::DecryptFspOwnerHandoffDropped => "decrypt_fsp_owner_handoff_dropped",
            Event::FmpAeadCompletionReplayDroppedPrechecked => {
                "fmp_aead_completion_replay_dropped_prechecked"
            }
            Event::FmpAeadCompletionReplayDroppedDeferred => {
                "fmp_aead_completion_replay_dropped_deferred"
            }
            Event::FmpAeadCompletionReplayDroppedDuplicate => {
                "fmp_aead_completion_replay_dropped_duplicate"
            }
            Event::FmpAeadCompletionReplayDroppedTooOld => {
                "fmp_aead_completion_replay_dropped_too_old"
            }
            Event::FmpAeadCompletionReplayDroppedTooOldLagGe2xWindow => {
                "fmp_aead_completion_replay_dropped_too_old_lag_ge_2x_window"
            }
            Event::FmpAeadCompletionReplayDroppedTooOldLagGe4xWindow => {
                "fmp_aead_completion_replay_dropped_too_old_lag_ge_4x_window"
            }
            Event::FmpAeadCompletionReplayDroppedTooOldLagGe16xWindow => {
                "fmp_aead_completion_replay_dropped_too_old_lag_ge_16x_window"
            }
            Event::FmpAeadCompletionReplayDroppedTooOldLagGe64xWindow => {
                "fmp_aead_completion_replay_dropped_too_old_lag_ge_64x_window"
            }
            Event::DecryptFspMalformedDropped => "decrypt_fsp_malformed_dropped",
            Event::FspAeadCompletionAeadFailedLocal => "fsp_aead_completion_aead_failed_local",
            Event::FspAeadCompletionAeadFailedHelper => "fsp_aead_completion_aead_failed_helper",
            Event::FspAeadCompletionAeadFailedHelperReturned => {
                "fsp_aead_completion_aead_failed_helper_returned"
            }
            Event::FspAeadCompletionAeadFailedWorkerOpen => {
                "fsp_aead_completion_aead_failed_worker_open"
            }
            Event::FspAeadCompletionAeadFailedWorkerOpenReturned => {
                "fsp_aead_completion_aead_failed_worker_open_returned"
            }
            Event::FspAeadCompletionEpochMismatch => "fsp_aead_completion_epoch_mismatch",
            Event::FspAeadCompletionAeadFailedLocalOpen => {
                "fsp_aead_completion_aead_failed_local_open"
            }
            Event::FspAeadCompletionAeadFailedAcceptKbitMismatch => {
                "fsp_aead_completion_aead_failed_accept_kbit_mismatch"
            }
            Event::DecryptWorkerSelectFspCompletionBatch => {
                "decrypt_worker_select_fsp_completion_batch"
            }
            Event::DecryptWorkerDrainAeadCompletionBatch => {
                "decrypt_worker_drain_aead_completion_batch"
            }
            Event::DecryptWorkerBulkInterleaveAeadCompletionBatch => {
                "decrypt_worker_bulk_interleave_aead_completion_batch"
            }
            Event::DecryptWorkerBatchWorker0 => "decrypt_worker_batch_worker0",
            Event::DecryptWorkerBatchWorker1 => "decrypt_worker_batch_worker1",
            Event::DecryptWorkerBatchWorker2 => "decrypt_worker_batch_worker2",
            Event::DecryptWorkerBatchWorker3 => "decrypt_worker_batch_worker3",
            Event::DecryptWorkerBatchWorker4 => "decrypt_worker_batch_worker4",
            Event::DecryptWorkerBatchWorker5 => "decrypt_worker_batch_worker5",
            Event::DecryptWorkerBatchWorker6 => "decrypt_worker_batch_worker6",
            Event::DecryptWorkerBatchWorker7 => "decrypt_worker_batch_worker7",
            Event::DecryptWorkerBatchWorkerOther => "decrypt_worker_batch_worker_other",
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
        65 => Event::FmpWorkerDispatchBatch,
        66 => Event::FmpWorkerDispatchPackets,
        67 => Event::DecryptWorkerBulkInputWaitGe250us,
        68 => Event::DecryptWorkerBulkInputWaitGe500us,
        69 => Event::DecryptWorkerBulkInputWaitGe1ms,
        70 => Event::DecryptFspOwnerSame,
        71 => Event::DecryptFspOwnerMismatch,
        72 => Event::DecryptFspPathLocal,
        73 => Event::DecryptFspPathHandoff,
        74 => Event::DecryptFspPathHelper,
        75 => Event::DecryptFspPathFallback,
        76 => Event::DecryptFmpPreownerHelper,
        77 => Event::DecryptFmpPreownerHelperFallback,
        78 => Event::DecryptFmpPreownerWindowFallback,
        79 => Event::DecryptFmpPreownerInlineFallback,
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
        91 => Event::FmpAeadCompletionReady,
        92 => Event::FmpAeadCompletionAccepted,
        93 => Event::FmpAeadCompletionAeadFailed,
        94 => Event::FmpAeadCompletionReplayDropped,
        95 => Event::FmpAeadCompletionReadyMulti,
        96 => Event::FspAeadCompletionReady,
        97 => Event::FspAeadCompletionAccepted,
        98 => Event::FspAeadCompletionAeadFailed,
        99 => Event::FspAeadCompletionReplayDropped,
        100 => Event::FspAeadCompletionReadyMulti,
        101 => Event::EndpointBulkFastPathPrepareFailed,
        102 => Event::EndpointBulkFastPathStageFull,
        103 => Event::EndpointBulkFastPathFeedbackFull,
        104 => Event::EndpointBulkFastPathAttempt,
        105 => Event::EndpointBulkFastPathDispatched,
        106 => Event::EndpointBulkFastPathLeaseMiss,
        107 => Event::EndpointBulkFastPathIneligible,
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
        118 => Event::EndpointCommittedBulkDispatchBatch,
        119 => Event::EndpointCommittedBulkDispatchPackets,
        120 => Event::EndpointCommittedBulkDispatchMergedBatch,
        121 => Event::EndpointCommittedBulkDispatchMergedPackets,
        122 => Event::FspAeadCompletionStaleSession,
        123 => Event::FspAeadCompletionStaleOrder,
        124 => Event::FspAeadCompletionStaleTicket,
        125 => Event::FspAeadCompletionDuplicateTicket,
        126 => Event::FspAeadCompletionWindowExceeded,
        127 => Event::DecryptFspOpenWorkerWindowFallback,
        128 => Event::DecryptWorkerSelectPriority,
        129 => Event::DecryptWorkerSelectFmpCompletion,
        130 => Event::DecryptWorkerSelectFspCompletionPackets,
        131 => Event::DecryptWorkerSelectBulkPackets,
        132 => Event::DecryptWorkerDrainPriority,
        133 => Event::DecryptWorkerDrainAeadCompletionPackets,
        134 => Event::DecryptWorkerDrainBulkPackets,
        135 => Event::DecryptWorkerBulkInterleaveAeadCompletionPackets,
        136 => Event::DecryptWorkerBulkInterleaveBudgetExhausted,
        137 => Event::DecryptFspPathWorkerOpen,
        138 => Event::DecryptWorkerControlDropped,
        139 => Event::DecryptWorkerSelectControl,
        140 => Event::DecryptWorkerDrainControl,
        141 => Event::DecryptFspHelperCompletionBacklogFallback,
        142 => Event::DecryptFspHelperQueueFullFallback,
        143 => Event::DecryptFmpHelperCompletionBacklogFallback,
        144 => Event::DecryptFmpPreownerCompletionBacklogFallback,
        145 => Event::DecryptFspOpenWorkerCompletionBacklogFallback,
        146 => Event::FspAeadCompletionReplayDroppedHelper,
        147 => Event::FspAeadCompletionReplayDroppedHelperReturned,
        148 => Event::FspAeadCompletionReplayDroppedWorkerOpen,
        149 => Event::FspAeadCompletionReplayDroppedWorkerOpenReturned,
        150 => Event::FspAeadCompletionReplayDroppedDuplicate,
        151 => Event::FspAeadCompletionReplayDroppedTooOld,
        152 => Event::FspAeadCompletionReplayDroppedTooOldLagGe2xWindow,
        153 => Event::FspAeadCompletionReplayDroppedTooOldLagGe4xWindow,
        154 => Event::FspAeadCompletionReplayDroppedTooOldLagGe16xWindow,
        155 => Event::FspAeadCompletionReplayDroppedTooOldLagGe64xWindow,
        156 => Event::ConnectedUdpDirectDecryptBulkShed,
        157 => Event::DecryptFspOpenPoolQueueFullFallback,
        158 => Event::ConnectedUdpKernelDropped,
        159 => Event::ConnectedUdpPeerKernelDropped,
        160 => Event::DecryptFspPathWorkerOpenStriped,
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
        175 => Event::ConnectedUdpDrainBulkDropped,
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
        186 => Event::DecryptFspPathHelperBulk,
        187 => Event::DecryptFspPathWorkerOpenBulk,
        188 => Event::FspAeadCompletionReturnedHelper,
        189 => Event::FspAeadCompletionReturnedWorkerOpen,
        190 => Event::DecryptFspOwnerHandoffDropped,
        191 => Event::FmpAeadCompletionReplayDroppedPrechecked,
        192 => Event::FmpAeadCompletionReplayDroppedDeferred,
        193 => Event::FmpAeadCompletionReplayDroppedDuplicate,
        194 => Event::FmpAeadCompletionReplayDroppedTooOld,
        195 => Event::FmpAeadCompletionReplayDroppedTooOldLagGe2xWindow,
        196 => Event::FmpAeadCompletionReplayDroppedTooOldLagGe4xWindow,
        197 => Event::FmpAeadCompletionReplayDroppedTooOldLagGe16xWindow,
        198 => Event::FmpAeadCompletionReplayDroppedTooOldLagGe64xWindow,
        199 => Event::DecryptFspMalformedDropped,
        200 => Event::FspAeadCompletionAeadFailedLocal,
        201 => Event::FspAeadCompletionAeadFailedHelper,
        202 => Event::FspAeadCompletionAeadFailedHelperReturned,
        203 => Event::FspAeadCompletionAeadFailedWorkerOpen,
        204 => Event::FspAeadCompletionAeadFailedWorkerOpenReturned,
        205 => Event::FspAeadCompletionEpochMismatch,
        206 => Event::FspAeadCompletionAeadFailedLocalOpen,
        207 => Event::FspAeadCompletionAeadFailedAcceptKbitMismatch,
        208 => Event::DecryptWorkerSelectFspCompletionBatch,
        209 => Event::DecryptWorkerDrainAeadCompletionBatch,
        210 => Event::DecryptWorkerBulkInterleaveAeadCompletionBatch,
        211 => Event::DecryptWorkerBatchWorker0,
        212 => Event::DecryptWorkerBatchWorker1,
        213 => Event::DecryptWorkerBatchWorker2,
        214 => Event::DecryptWorkerBatchWorker3,
        215 => Event::DecryptWorkerBatchWorker4,
        216 => Event::DecryptWorkerBatchWorker5,
        217 => Event::DecryptWorkerBatchWorker6,
        218 => Event::DecryptWorkerBatchWorker7,
        219 => Event::DecryptWorkerBatchWorkerOther,
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
pub(crate) fn record_connected_udp_peer_kernel_drops(drops: u64) {
    record_event_count(Event::ConnectedUdpPeerKernelDropped, drops);
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
fn record_fmp_send_group_split(event: Event) {
    if !enabled() {
        return;
    }
    record_event_count_sample(event, 1);
}

#[inline]
pub(crate) fn record_endpoint_committed_bulk_dispatch(
    packets: usize,
    merged_batches: usize,
    merged_packets: usize,
) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::EndpointCommittedBulkDispatchBatch, 1);
    record_event_count_sample(Event::EndpointCommittedBulkDispatchPackets, packets as u64);
    if merged_batches > 0 {
        record_event_count_sample(
            Event::EndpointCommittedBulkDispatchMergedBatch,
            merged_batches as u64,
        );
    }
    if merged_packets > 0 {
        record_event_count_sample(
            Event::EndpointCommittedBulkDispatchMergedPackets,
            merged_packets as u64,
        );
    }
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
pub(crate) fn record_decrypt_worker_select_fmp_completion() {
    record_event(Event::DecryptWorkerSelectFmpCompletion);
}

#[inline]
pub(crate) fn record_decrypt_worker_select_fsp_completion(packets: usize) {
    record_event(Event::DecryptWorkerSelectFspCompletionBatch);
    record_event_count(
        Event::DecryptWorkerSelectFspCompletionPackets,
        packets as u64,
    );
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
pub(crate) fn record_decrypt_worker_drain_aead_completion(messages: usize, packets: usize) {
    record_event_count(
        Event::DecryptWorkerDrainAeadCompletionBatch,
        messages as u64,
    );
    record_event_count(
        Event::DecryptWorkerDrainAeadCompletionPackets,
        packets as u64,
    );
}

#[inline]
pub(crate) fn record_decrypt_worker_drain_bulk(packets: usize) {
    record_event_count(Event::DecryptWorkerDrainBulkPackets, packets as u64);
}

#[inline]
pub(crate) fn record_decrypt_worker_bulk_interleave_aead_completion(
    messages: usize,
    packets: usize,
) {
    record_event_count(
        Event::DecryptWorkerBulkInterleaveAeadCompletionBatch,
        messages as u64,
    );
    record_event_count(
        Event::DecryptWorkerBulkInterleaveAeadCompletionPackets,
        packets as u64,
    );
}

#[inline]
pub(crate) fn record_decrypt_worker_bulk_interleave_budget_exhausted() {
    record_event(Event::DecryptWorkerBulkInterleaveBudgetExhausted);
}

#[inline]
pub(crate) fn record_fmp_aead_completion_drain(
    ready: usize,
    accepted: usize,
    aead_failures: usize,
    replay_drops: usize,
) {
    if !enabled() || ready == 0 {
        return;
    }
    record_event_count_sample(Event::FmpAeadCompletionReady, ready as u64);
    if accepted > 0 {
        record_event_count_sample(Event::FmpAeadCompletionAccepted, accepted as u64);
    }
    if aead_failures > 0 {
        record_event_count_sample(Event::FmpAeadCompletionAeadFailed, aead_failures as u64);
    }
    if replay_drops > 0 {
        record_event_count_sample(Event::FmpAeadCompletionReplayDropped, replay_drops as u64);
    }
    if ready > 1 {
        record_event_count_sample(Event::FmpAeadCompletionReadyMulti, 1);
    }
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
pub(crate) fn record_fsp_aead_completion_source_replay_drops(
    helper: usize,
    helper_returned: usize,
    worker_open: usize,
    worker_open_returned: usize,
) {
    if !enabled() {
        return;
    }
    if helper > 0 {
        record_event_count_sample(Event::FspAeadCompletionReplayDroppedHelper, helper as u64);
    }
    if helper_returned > 0 {
        record_event_count_sample(
            Event::FspAeadCompletionReplayDroppedHelperReturned,
            helper_returned as u64,
        );
    }
    if worker_open > 0 {
        record_event_count_sample(
            Event::FspAeadCompletionReplayDroppedWorkerOpen,
            worker_open as u64,
        );
    }
    if worker_open_returned > 0 {
        record_event_count_sample(
            Event::FspAeadCompletionReplayDroppedWorkerOpenReturned,
            worker_open_returned as u64,
        );
    }
}

#[inline]
pub(crate) fn record_fsp_aead_completion_source_aead_failures(
    local: usize,
    helper: usize,
    helper_returned: usize,
    worker_open: usize,
    worker_open_returned: usize,
) {
    if !enabled() {
        return;
    }
    if local > 0 {
        record_event_count_sample(Event::FspAeadCompletionAeadFailedLocal, local as u64);
    }
    if helper > 0 {
        record_event_count_sample(Event::FspAeadCompletionAeadFailedHelper, helper as u64);
    }
    if helper_returned > 0 {
        record_event_count_sample(
            Event::FspAeadCompletionAeadFailedHelperReturned,
            helper_returned as u64,
        );
    }
    if worker_open > 0 {
        record_event_count_sample(
            Event::FspAeadCompletionAeadFailedWorkerOpen,
            worker_open as u64,
        );
    }
    if worker_open_returned > 0 {
        record_event_count_sample(
            Event::FspAeadCompletionAeadFailedWorkerOpenReturned,
            worker_open_returned as u64,
        );
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
pub(crate) fn record_fmp_aead_completion_replay_drop_mode(deferred: bool) {
    if !enabled() {
        return;
    }
    record_event(if deferred {
        Event::FmpAeadCompletionReplayDroppedDeferred
    } else {
        Event::FmpAeadCompletionReplayDroppedPrechecked
    });
}

#[inline]
pub(crate) fn record_fmp_aead_completion_replay_drop_reason(
    reason: crate::noise::ReplayRejection,
    counter_lag: u64,
) {
    if !enabled() {
        return;
    }
    let event = match reason {
        crate::noise::ReplayRejection::Duplicate => Event::FmpAeadCompletionReplayDroppedDuplicate,
        crate::noise::ReplayRejection::TooOld => Event::FmpAeadCompletionReplayDroppedTooOld,
    };
    record_event(event);
    if reason == crate::noise::ReplayRejection::TooOld {
        record_fmp_aead_completion_too_old_lag_buckets(counter_lag);
    }
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
fn record_fmp_aead_completion_too_old_lag_buckets(counter_lag: u64) {
    let window = crate::noise::REPLAY_WINDOW_SIZE as u64;
    if counter_lag >= window.saturating_mul(2) {
        record_event(Event::FmpAeadCompletionReplayDroppedTooOldLagGe2xWindow);
    }
    if counter_lag >= window.saturating_mul(4) {
        record_event(Event::FmpAeadCompletionReplayDroppedTooOldLagGe4xWindow);
    }
    if counter_lag >= window.saturating_mul(16) {
        record_event(Event::FmpAeadCompletionReplayDroppedTooOldLagGe16xWindow);
    }
    if counter_lag >= window.saturating_mul(64) {
        record_event(Event::FmpAeadCompletionReplayDroppedTooOldLagGe64xWindow);
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
