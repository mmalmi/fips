//! Runtime perf profiler for the packet_mover2 hot path and queue handoffs.
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
//! Live stages track UDP receive/send, TUN and endpoint output, bounded
//! transport/endpoint queue residence, PM2 stateless AEAD service, and PM2
//! ordered retirement. Historical slots stay reserved so old logs remain
//! index-comparable without advertising retired paths.

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
const N_EVENTS: usize = 245;
const HIST_BUCKETS: usize = 48;

/// Stage identifier. `as usize` indexes into the counter arrays.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Stage {
    UdpRecv = 0,
    ReservedStage1 = 1,
    ReservedStage2 = 2,
    ReservedStage3 = 3,
    TunWrite = 4,
    ReservedStage5 = 5,
    ReservedStage6 = 6,
    UdpSend = 7,
    ReservedStage8 = 8,
    EndpointDeliver = 9,
    ReservedStage10 = 10,
    ReservedStage11 = 11,
    ReservedStage12 = 12,
    ReservedStage13 = 13,
    ReservedStage14 = 14,
    EndpointEventWait = 15,
    ReservedStage16 = 16,
    ReservedStage17 = 17,
    ReservedStage18 = 18,
    ReservedStage19 = 19,
    TransportChannelWait = 20,
    TransportPriorityChannelWait = 21,
    TransportBulkChannelWait = 22,
    TransportRxLoopOwnedWait = 23,
    ReservedStage24 = 24,
    ReservedStage25 = 25,
    ReservedStage26 = 26,
    ReservedStage27 = 27,
    ReservedStage28 = 28,
    ReservedStage29 = 29,
    ReservedStage30 = 30,
    ReservedStage31 = 31,
    ReservedStage32 = 32,
    ReservedStage33 = 33,
    ReservedStage34 = 34,
    ReservedStage35 = 35,
    ReservedStage36 = 36,
    ReservedStage37 = 37,
    ReservedStage38 = 38,
    ReservedStage39 = 39,
    ReservedStage40 = 40,
    ReservedStage41 = 41,
    ReservedStage42 = 42,
    ReservedStage43 = 43,
    ReservedStage44 = 44,
    ReservedStage45 = 45,
    ReservedStage46 = 46,
    ReservedStage47 = 47,
    ReservedStage48 = 48,
    ReservedStage49 = 49,
    ReservedStage50 = 50,
    ReservedStage51 = 51,
    ReservedStage52 = 52,
    PacketMover2AeadOpen = 53,
    PacketMover2AeadSeal = 54,
    PacketMover2Retire = 55,
    PacketMover2FspOwnerSync = 56,
    PacketMover2LiveTurn = 57,
    PacketMover2CompletionDrain = 58,
    PacketMover2LiveAdmit = 59,
    PacketMover2AeadDispatch = 60,
    PacketMover2OutputSink = 61,
    PacketMover2TransportSend = 62,
    PacketMover2TransportSendWorker = 63,
    PacketMover2OwnerDispatch = 64,
    PacketMover2ExecutorSubmit = 65,
    PacketMover2CompletionQueue = 66,
    PacketMover2AeadWorkerQueueWait = 67,
    ReservedStage68 = 68,
}

impl Stage {
    const fn name(self) -> &'static str {
        match self {
            Stage::UdpRecv => "udp_recv",
            Stage::ReservedStage1 => "reserved_stage_1",
            Stage::ReservedStage2 => "reserved_stage_2",
            Stage::ReservedStage3 => "reserved_stage_3",
            Stage::TunWrite => "tun_write",
            Stage::ReservedStage5 => "reserved_stage_5",
            Stage::ReservedStage6 => "reserved_stage_6",
            Stage::UdpSend => "udp_send",
            Stage::ReservedStage8 => "reserved_stage_8",
            Stage::EndpointDeliver => "endpoint_deliver",
            Stage::ReservedStage10 => "reserved_stage_10",
            Stage::ReservedStage11 => "reserved_stage_11",
            Stage::ReservedStage12 => "reserved_stage_12",
            Stage::ReservedStage13 => "reserved_stage_13",
            Stage::ReservedStage14 => "reserved_stage_14",
            Stage::EndpointEventWait => "endpoint_event_wait",
            Stage::ReservedStage16 => "reserved_stage_16",
            Stage::ReservedStage17 => "reserved_stage_17",
            Stage::ReservedStage18 => "reserved_stage_18",
            Stage::ReservedStage19 => "reserved_stage_19",
            Stage::TransportChannelWait => "transport_channel_wait",
            Stage::TransportPriorityChannelWait => "transport_priority_channel_wait",
            Stage::TransportBulkChannelWait => "transport_bulk_channel_wait",
            Stage::TransportRxLoopOwnedWait => "transport_rx_loop_owned_wait",
            Stage::ReservedStage24 => "reserved_stage_24",
            Stage::ReservedStage25 => "reserved_stage_25",
            Stage::ReservedStage26 => "reserved_stage_26",
            Stage::ReservedStage27 => "reserved_stage_27",
            Stage::ReservedStage28 => "reserved_stage_28",
            Stage::ReservedStage29 => "reserved_stage_29",
            Stage::ReservedStage30 => "reserved_stage_30",
            Stage::ReservedStage31 => "reserved_stage_31",
            Stage::ReservedStage32 => "reserved_stage_32",
            Stage::ReservedStage33 => "reserved_stage_33",
            Stage::ReservedStage34 => "reserved_stage_34",
            Stage::ReservedStage35 => "reserved_stage_35",
            Stage::ReservedStage36 => "reserved_stage_36",
            Stage::ReservedStage37 => "reserved_stage_37",
            Stage::ReservedStage38 => "reserved_stage_38",
            Stage::ReservedStage39 => "reserved_stage_39",
            Stage::ReservedStage40 => "reserved_stage_40",
            Stage::ReservedStage41 => "reserved_stage_41",
            Stage::ReservedStage42 => "reserved_stage_42",
            Stage::ReservedStage43 => "reserved_stage_43",
            Stage::ReservedStage44 => "reserved_stage_44",
            Stage::ReservedStage45 => "reserved_stage_45",
            Stage::ReservedStage46 => "reserved_stage_46",
            Stage::ReservedStage47 => "reserved_stage_47",
            Stage::ReservedStage48 => "reserved_stage_48",
            Stage::ReservedStage49 => "reserved_stage_49",
            Stage::ReservedStage50 => "reserved_stage_50",
            Stage::ReservedStage51 => "reserved_stage_51",
            Stage::ReservedStage52 => "reserved_stage_52",
            Stage::PacketMover2AeadOpen => "packet_mover2_aead_open",
            Stage::PacketMover2AeadSeal => "packet_mover2_aead_seal",
            Stage::PacketMover2Retire => "packet_mover2_retire",
            Stage::PacketMover2FspOwnerSync => "packet_mover2_fsp_owner_sync",
            Stage::PacketMover2LiveTurn => "packet_mover2_live_turn",
            Stage::PacketMover2CompletionDrain => "packet_mover2_completion_drain",
            Stage::PacketMover2LiveAdmit => "packet_mover2_live_admit",
            Stage::PacketMover2AeadDispatch => "packet_mover2_aead_dispatch",
            Stage::PacketMover2OutputSink => "packet_mover2_output_sink",
            Stage::PacketMover2TransportSend => "packet_mover2_transport_send",
            Stage::PacketMover2TransportSendWorker => "packet_mover2_transport_send_worker",
            Stage::PacketMover2OwnerDispatch => "packet_mover2_owner_dispatch",
            Stage::PacketMover2ExecutorSubmit => "packet_mover2_executor_submit",
            Stage::PacketMover2CompletionQueue => "packet_mover2_completion_queue",
            Stage::PacketMover2AeadWorkerQueueWait => "packet_mover2_aead_worker_queue_wait",
            Stage::ReservedStage68 => "reserved_stage_68",
        }
    }
}

fn stage_from_index(idx: usize) -> Stage {
    match idx {
        0 => Stage::UdpRecv,
        1 => Stage::ReservedStage1,
        2 => Stage::ReservedStage2,
        3 => Stage::ReservedStage3,
        4 => Stage::TunWrite,
        5 => Stage::ReservedStage5,
        6 => Stage::ReservedStage6,
        7 => Stage::UdpSend,
        8 => Stage::ReservedStage8,
        9 => Stage::EndpointDeliver,
        10 => Stage::ReservedStage10,
        11 => Stage::ReservedStage11,
        12 => Stage::ReservedStage12,
        13 => Stage::ReservedStage13,
        14 => Stage::ReservedStage14,
        15 => Stage::EndpointEventWait,
        16 => Stage::ReservedStage16,
        17 => Stage::ReservedStage17,
        18 => Stage::ReservedStage18,
        19 => Stage::ReservedStage19,
        20 => Stage::TransportChannelWait,
        21 => Stage::TransportPriorityChannelWait,
        22 => Stage::TransportBulkChannelWait,
        23 => Stage::TransportRxLoopOwnedWait,
        24 => Stage::ReservedStage24,
        25 => Stage::ReservedStage25,
        26 => Stage::ReservedStage26,
        27 => Stage::ReservedStage27,
        28 => Stage::ReservedStage28,
        29 => Stage::ReservedStage29,
        30 => Stage::ReservedStage30,
        31 => Stage::ReservedStage31,
        32 => Stage::ReservedStage32,
        33 => Stage::ReservedStage33,
        34 => Stage::ReservedStage34,
        35 => Stage::ReservedStage35,
        36 => Stage::ReservedStage36,
        37 => Stage::ReservedStage37,
        38 => Stage::ReservedStage38,
        39 => Stage::ReservedStage39,
        40 => Stage::ReservedStage40,
        41 => Stage::ReservedStage41,
        42 => Stage::ReservedStage42,
        43 => Stage::ReservedStage43,
        44 => Stage::ReservedStage44,
        45 => Stage::ReservedStage45,
        46 => Stage::ReservedStage46,
        47 => Stage::ReservedStage47,
        48 => Stage::ReservedStage48,
        49 => Stage::ReservedStage49,
        50 => Stage::ReservedStage50,
        51 => Stage::ReservedStage51,
        52 => Stage::ReservedStage52,
        53 => Stage::PacketMover2AeadOpen,
        54 => Stage::PacketMover2AeadSeal,
        55 => Stage::PacketMover2Retire,
        56 => Stage::PacketMover2FspOwnerSync,
        57 => Stage::PacketMover2LiveTurn,
        58 => Stage::PacketMover2CompletionDrain,
        59 => Stage::PacketMover2LiveAdmit,
        60 => Stage::PacketMover2AeadDispatch,
        61 => Stage::PacketMover2OutputSink,
        62 => Stage::PacketMover2TransportSend,
        63 => Stage::PacketMover2TransportSendWorker,
        64 => Stage::PacketMover2OwnerDispatch,
        65 => Stage::PacketMover2ExecutorSubmit,
        66 => Stage::PacketMover2CompletionQueue,
        67 => Stage::PacketMover2AeadWorkerQueueWait,
        68 => Stage::ReservedStage68,
        _ => unreachable!(),
    }
}
/// Count-only events that clarify which current hot-path variant is active.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Event {
    ReservedEvent0 = 0,
    ReservedEvent1 = 1,
    ReservedEvent2 = 2,
    ReservedEvent3 = 3,
    ReservedEvent4 = 4,
    ReservedEvent5 = 5,
    ReservedEvent6 = 6,
    ReservedEvent7 = 7,
    ReservedEvent8 = 8,
    ReservedEvent9 = 9,
    ReservedEvent10 = 10,
    ReservedEvent11 = 11,
    ReservedEvent12 = 12,
    ReservedEvent13 = 13,
    ReservedEvent14 = 14,
    ReservedEvent15 = 15,
    PendingTunDestinationDropped = 16,
    PendingTunPacketDropped = 17,
    PendingEndpointDestinationDropped = 18,
    PendingEndpointPacketDropped = 19,
    ReservedEvent20 = 20,
    EndpointEventBacklogHigh = 21,
    EndpointDataBulkDropped = 22,
    TransportChannelBacklogHigh = 23,
    TransportBulkDropped = 24,
    EndpointEventBulkDropped = 25,
    ReservedEvent26 = 26,
    ReservedEvent27 = 27,
    ReservedEvent28 = 28,
    RxLoopSlowMaintenanceTimeout = 29,
    RxLoopSlowMaintenanceSkipped = 30,
    ReservedEvent31 = 31,
    ReservedEvent32 = 32,
    ReservedEvent33 = 33,
    ReservedEvent34 = 34,
    ReservedEvent35 = 35,
    ReservedEvent36 = 36,
    ReservedEvent37 = 37,
    ReservedEvent38 = 38,
    ReservedEvent39 = 39,
    ReservedEvent40 = 40,
    ReservedEvent41 = 41,
    ReservedEvent42 = 42,
    ReservedEvent43 = 43,
    ReservedEvent44 = 44,
    ReservedEvent45 = 45,
    UdpSendSendmmsgBatch = 46,
    UdpSendSendmmsgPackets = 47,
    UdpSendGsoBatch = 48,
    UdpSendGsoPackets = 49,
    UdpSendGsoBatchGe32 = 50,
    UdpSendGsoBatchGe48 = 51,
    UdpSendGsoBatchEq64 = 52,
    ReservedEvent53 = 53,
    ReservedEvent54 = 54,
    ReservedEvent55 = 55,
    ReservedEvent56 = 56,
    UdpSendSendmmsgBatchGe32 = 57,
    UdpSendSendmmsgBatchGe48 = 58,
    UdpSendSendmmsgBatchEq64 = 59,
    ReservedEvent60 = 60,
    ReservedEvent61 = 61,
    ReservedEvent62 = 62,
    ReservedEvent63 = 63,
    ReservedEvent64 = 64,
    ReservedEvent65 = 65,
    ReservedEvent66 = 66,
    ReservedEvent67 = 67,
    ReservedEvent68 = 68,
    ReservedEvent69 = 69,
    ReservedEvent70 = 70,
    ReservedEvent71 = 71,
    ReservedEvent72 = 72,
    ReservedEvent73 = 73,
    ReservedEvent74 = 74,
    ReservedEvent75 = 75,
    ReservedEvent76 = 76,
    ReservedEvent77 = 77,
    ReservedEvent78 = 78,
    ReservedEvent79 = 79,
    ReservedEvent80 = 80,
    ReservedEvent81 = 81,
    ReservedEvent82 = 82,
    ReservedEvent83 = 83,
    ReservedEvent84 = 84,
    ReservedEvent85 = 85,
    ReservedEvent86 = 86,
    ReservedEvent87 = 87,
    ReservedEvent88 = 88,
    ReservedEvent89 = 89,
    ReservedEvent90 = 90,
    ReservedEvent91 = 91,
    ReservedEvent92 = 92,
    ReservedEvent93 = 93,
    ReservedEvent94 = 94,
    ReservedEvent95 = 95,
    ReservedEvent96 = 96,
    ReservedEvent97 = 97,
    ReservedEvent98 = 98,
    ReservedEvent99 = 99,
    ReservedEvent100 = 100,
    ReservedEvent101 = 101,
    ReservedEvent102 = 102,
    ReservedEvent103 = 103,
    ReservedEvent104 = 104,
    ReservedEvent105 = 105,
    ReservedEvent106 = 106,
    ReservedEvent107 = 107,
    ReservedEvent108 = 108,
    ReservedEvent109 = 109,
    ReservedEvent110 = 110,
    ReservedEvent111 = 111,
    ReservedEvent112 = 112,
    ReservedEvent113 = 113,
    ReservedEvent114 = 114,
    ReservedEvent115 = 115,
    ReservedEvent116 = 116,
    ReservedEvent117 = 117,
    ReservedEvent118 = 118,
    ReservedEvent119 = 119,
    ReservedEvent120 = 120,
    ReservedEvent121 = 121,
    ReservedEvent122 = 122,
    ReservedEvent123 = 123,
    ReservedEvent124 = 124,
    ReservedEvent125 = 125,
    ReservedEvent126 = 126,
    ReservedEvent127 = 127,
    ReservedEvent128 = 128,
    ReservedEvent129 = 129,
    ReservedEvent130 = 130,
    ReservedEvent131 = 131,
    ReservedEvent132 = 132,
    ReservedEvent133 = 133,
    ReservedEvent134 = 134,
    ReservedEvent135 = 135,
    ReservedEvent136 = 136,
    ReservedEvent137 = 137,
    ReservedEvent138 = 138,
    ReservedEvent139 = 139,
    ReservedEvent140 = 140,
    ReservedEvent141 = 141,
    ReservedEvent142 = 142,
    ReservedEvent143 = 143,
    ReservedEvent144 = 144,
    ReservedEvent145 = 145,
    ReservedEvent146 = 146,
    ReservedEvent147 = 147,
    ReservedEvent148 = 148,
    ReservedEvent149 = 149,
    ReservedEvent150 = 150,
    ReservedEvent151 = 151,
    ReservedEvent152 = 152,
    ReservedEvent153 = 153,
    ReservedEvent154 = 154,
    ReservedEvent155 = 155,
    ReservedEvent156 = 156,
    ReservedEvent157 = 157,
    ReservedEvent158 = 158,
    ReservedEvent159 = 159,
    ReservedEvent160 = 160,
    ReservedEvent161 = 161,
    EndpointEventBulkBacklogHigh = 162,
    PacketBatchPoolFresh = 163,
    PacketBatchPoolReuse = 164,
    PacketBatchPoolReturn = 165,
    PacketBatchPoolDiscard = 166,
    PacketBufferPoolFresh = 167,
    PacketBufferPoolReuse = 168,
    PacketBufferPoolReturn = 169,
    PacketBufferPoolDiscard = 170,
    ReservedEvent171 = 171,
    UdpKernelDropped = 172,
    UdpSocketKernelDropped = 173,
    UdpNamespaceRcvbufErrors = 174,
    ReservedEvent175 = 175,
    ReservedEvent176 = 176,
    ReservedEvent177 = 177,
    ReservedEvent178 = 178,
    ReservedEvent179 = 179,
    ReservedEvent180 = 180,
    ReservedEvent181 = 181,
    ReservedEvent182 = 182,
    ReservedEvent183 = 183,
    ReservedEvent184 = 184,
    ReservedEvent185 = 185,
    TunWriteBulkDropped = 186,
    TunWriteBulkBacklogHigh = 187,
    PacketMover2FspPathOpen = 188,
    PacketMover2FspPathOpenBulk = 189,
    PacketMover2FspOwnerSyncCall = 190,
    PacketMover2CryptoOpenBatch = 191,
    PacketMover2CryptoOpenPackets = 192,
    PacketMover2CryptoSealBatch = 193,
    PacketMover2CryptoSealPackets = 194,
    PacketMover2CryptoBatchSingle = 195,
    PacketMover2CryptoBatchGe8 = 196,
    PacketMover2CryptoBatchGe32 = 197,
    PacketMover2CryptoBatchGe64 = 198,
    ReservedEvent199 = 199,
    PacketMover2FspOwnerSyncApplied = 200,
    PacketMover2DispatchOwnerBlocked = 201,
    PacketMover2DispatchNoIngress = 202,
    PacketMover2DispatchLimitHit = 203,
    PacketMover2DispatchExecutorFull = 204,
    PacketMover2DispatchOwnerBlockedTotal = 205,
    PacketMover2DispatchOwnerBlockedBulkLane = 206,
    ReservedEvent207 = 207,
    PacketMover2SealInPlace = 208,
    PacketMover2SealAllocated = 209,
    PacketMover2TransportSendWorkerBackpressure = 210,
    PacketMover2TransportSendWorkerDropped = 211,
    PacketMover2IngressOwnerRunContinue = 212,
    PacketMover2OutboundOwnerRunContinue = 213,
    PacketMover2OutboundBatchAdmit = 214,
    PacketMover2OutboundBatchPackets = 215,
    PacketMover2TransportSendWorkerSendFailed = 216,
    ReservedEvent217 = 217,
    ReservedEvent218 = 218,
    ReservedEvent219 = 219,
    ReservedEvent220 = 220,
    PacketMover2LiveRawAdmitted = 221,
    PacketMover2LiveEndpointAdmitted = 222,
    PacketMover2LiveTunAdmitted = 223,
    PacketMover2LivePreparedDispatched = 224,
    PacketMover2LiveCompletionsDrained = 225,
    PacketMover2LiveRetiredOutputs = 226,
    PacketMover2LiveRetiredDrops = 227,
    PacketMover2LiveOutputDrops = 228,
    PacketMover2AeadOpenInFlight = 229,
    PacketMover2AeadSealInFlight = 230,
    PacketMover2AeadCompletionQueueDepth = 231,
    PacketMover2AeadCompletionBatch = 232,
    PacketMover2AeadCompletionBatchPackets = 233,
    PacketMover2AeadPreparedJob = 234,
    PacketMover2AeadPreparedJobPackets = 235,
    PacketMover2LiveCompletionsRetired = 236,
    PacketMover2LiveOutputBatch = 237,
    PacketMover2LiveOutputBatchPackets = 238,
    PacketMover2AeadOpenQueueDepth = 239,
    PacketMover2AeadSealQueueDepth = 240,
    PacketMover2FastIngressOwnerRuns = 241,
    PacketMover2FastIngressOwnerRunPackets = 242,
    PacketMover2EstablishedFspDataRetireRuns = 243,
    PacketMover2EstablishedFspDataRetirePackets = 244,
}

impl Event {
    const fn name(self) -> &'static str {
        match self {
            Event::ReservedEvent0 => "reserved_event_0",
            Event::ReservedEvent1 => "reserved_event_1",
            Event::ReservedEvent2 => "reserved_event_2",
            Event::ReservedEvent3 => "reserved_event_3",
            Event::ReservedEvent4 => "reserved_event_4",
            Event::ReservedEvent5 => "reserved_event_5",
            Event::ReservedEvent6 => "reserved_event_6",
            Event::ReservedEvent7 => "reserved_event_7",
            Event::ReservedEvent8 => "reserved_event_8",
            Event::ReservedEvent9 => "reserved_event_9",
            Event::ReservedEvent10 => "reserved_event_10",
            Event::ReservedEvent11 => "reserved_event_11",
            Event::ReservedEvent12 => "reserved_event_12",
            Event::ReservedEvent13 => "reserved_event_13",
            Event::ReservedEvent14 => "reserved_event_14",
            Event::ReservedEvent15 => "reserved_event_15",
            Event::PendingTunDestinationDropped => "pending_tun_destination_dropped",
            Event::PendingTunPacketDropped => "pending_tun_packet_dropped",
            Event::PendingEndpointDestinationDropped => "pending_endpoint_destination_dropped",
            Event::PendingEndpointPacketDropped => "pending_endpoint_packet_dropped",
            Event::ReservedEvent20 => "reserved_event_20",
            Event::EndpointEventBacklogHigh => "endpoint_event_backlog_high",
            Event::EndpointDataBulkDropped => "endpoint_data_bulk_dropped",
            Event::TransportChannelBacklogHigh => "transport_channel_backlog_high",
            Event::TransportBulkDropped => "transport_bulk_dropped",
            Event::EndpointEventBulkDropped => "endpoint_event_bulk_dropped",
            Event::ReservedEvent26 => "reserved_event_26",
            Event::ReservedEvent27 => "reserved_event_27",
            Event::ReservedEvent28 => "reserved_event_28",
            Event::RxLoopSlowMaintenanceTimeout => "rx_loop_slow_maintenance_timeout",
            Event::RxLoopSlowMaintenanceSkipped => "rx_loop_slow_maintenance_skipped",
            Event::ReservedEvent31 => "reserved_event_31",
            Event::ReservedEvent32 => "reserved_event_32",
            Event::ReservedEvent33 => "reserved_event_33",
            Event::ReservedEvent34 => "reserved_event_34",
            Event::ReservedEvent35 => "reserved_event_35",
            Event::ReservedEvent36 => "reserved_event_36",
            Event::ReservedEvent37 => "reserved_event_37",
            Event::ReservedEvent38 => "reserved_event_38",
            Event::ReservedEvent39 => "reserved_event_39",
            Event::ReservedEvent40 => "reserved_event_40",
            Event::ReservedEvent41 => "reserved_event_41",
            Event::ReservedEvent42 => "reserved_event_42",
            Event::ReservedEvent43 => "reserved_event_43",
            Event::ReservedEvent44 => "reserved_event_44",
            Event::ReservedEvent45 => "reserved_event_45",
            Event::UdpSendSendmmsgBatch => "udp_send_sendmmsg_batch",
            Event::UdpSendSendmmsgPackets => "udp_send_sendmmsg_packets",
            Event::UdpSendGsoBatch => "udp_send_gso_batch",
            Event::UdpSendGsoPackets => "udp_send_gso_packets",
            Event::UdpSendGsoBatchGe32 => "udp_send_gso_batch_ge32",
            Event::UdpSendGsoBatchGe48 => "udp_send_gso_batch_ge48",
            Event::UdpSendGsoBatchEq64 => "udp_send_gso_batch_eq64",
            Event::ReservedEvent53 => "reserved_event_53",
            Event::ReservedEvent54 => "reserved_event_54",
            Event::ReservedEvent55 => "reserved_event_55",
            Event::ReservedEvent56 => "reserved_event_56",
            Event::UdpSendSendmmsgBatchGe32 => "udp_send_sendmmsg_batch_ge32",
            Event::UdpSendSendmmsgBatchGe48 => "udp_send_sendmmsg_batch_ge48",
            Event::UdpSendSendmmsgBatchEq64 => "udp_send_sendmmsg_batch_eq64",
            Event::ReservedEvent60 => "reserved_event_60",
            Event::ReservedEvent61 => "reserved_event_61",
            Event::ReservedEvent62 => "reserved_event_62",
            Event::ReservedEvent63 => "reserved_event_63",
            Event::ReservedEvent64 => "reserved_event_64",
            Event::ReservedEvent65 => "reserved_event_65",
            Event::ReservedEvent66 => "reserved_event_66",
            Event::ReservedEvent67 => "reserved_event_67",
            Event::ReservedEvent68 => "reserved_event_68",
            Event::ReservedEvent69 => "reserved_event_69",
            Event::ReservedEvent70 => "reserved_event_70",
            Event::ReservedEvent71 => "reserved_event_71",
            Event::ReservedEvent72 => "reserved_event_72",
            Event::ReservedEvent73 => "reserved_event_73",
            Event::ReservedEvent74 => "reserved_event_74",
            Event::ReservedEvent75 => "reserved_event_75",
            Event::ReservedEvent76 => "reserved_event_76",
            Event::ReservedEvent77 => "reserved_event_77",
            Event::ReservedEvent78 => "reserved_event_78",
            Event::ReservedEvent79 => "reserved_event_79",
            Event::ReservedEvent80 => "reserved_event_80",
            Event::ReservedEvent81 => "reserved_event_81",
            Event::ReservedEvent82 => "reserved_event_82",
            Event::ReservedEvent83 => "reserved_event_83",
            Event::ReservedEvent84 => "reserved_event_84",
            Event::ReservedEvent85 => "reserved_event_85",
            Event::ReservedEvent86 => "reserved_event_86",
            Event::ReservedEvent87 => "reserved_event_87",
            Event::ReservedEvent88 => "reserved_event_88",
            Event::ReservedEvent89 => "reserved_event_89",
            Event::ReservedEvent90 => "reserved_event_90",
            Event::ReservedEvent91 => "reserved_event_91",
            Event::ReservedEvent92 => "reserved_event_92",
            Event::ReservedEvent93 => "reserved_event_93",
            Event::ReservedEvent94 => "reserved_event_94",
            Event::ReservedEvent95 => "reserved_event_95",
            Event::ReservedEvent96 => "reserved_event_96",
            Event::ReservedEvent97 => "reserved_event_97",
            Event::ReservedEvent98 => "reserved_event_98",
            Event::ReservedEvent99 => "reserved_event_99",
            Event::ReservedEvent100 => "reserved_event_100",
            Event::ReservedEvent101 => "reserved_event_101",
            Event::ReservedEvent102 => "reserved_event_102",
            Event::ReservedEvent103 => "reserved_event_103",
            Event::ReservedEvent104 => "reserved_event_104",
            Event::ReservedEvent105 => "reserved_event_105",
            Event::ReservedEvent106 => "reserved_event_106",
            Event::ReservedEvent107 => "reserved_event_107",
            Event::ReservedEvent108 => "reserved_event_108",
            Event::ReservedEvent109 => "reserved_event_109",
            Event::ReservedEvent110 => "reserved_event_110",
            Event::ReservedEvent111 => "reserved_event_111",
            Event::ReservedEvent112 => "reserved_event_112",
            Event::ReservedEvent113 => "reserved_event_113",
            Event::ReservedEvent114 => "reserved_event_114",
            Event::ReservedEvent115 => "reserved_event_115",
            Event::ReservedEvent116 => "reserved_event_116",
            Event::ReservedEvent117 => "reserved_event_117",
            Event::ReservedEvent118 => "reserved_event_118",
            Event::ReservedEvent119 => "reserved_event_119",
            Event::ReservedEvent120 => "reserved_event_120",
            Event::ReservedEvent121 => "reserved_event_121",
            Event::ReservedEvent122 => "reserved_event_122",
            Event::ReservedEvent123 => "reserved_event_123",
            Event::ReservedEvent124 => "reserved_event_124",
            Event::ReservedEvent125 => "reserved_event_125",
            Event::ReservedEvent126 => "reserved_event_126",
            Event::ReservedEvent127 => "reserved_event_127",
            Event::ReservedEvent128 => "reserved_event_128",
            Event::ReservedEvent129 => "reserved_event_129",
            Event::ReservedEvent130 => "reserved_event_130",
            Event::ReservedEvent131 => "reserved_event_131",
            Event::ReservedEvent132 => "reserved_event_132",
            Event::ReservedEvent133 => "reserved_event_133",
            Event::ReservedEvent134 => "reserved_event_134",
            Event::ReservedEvent135 => "reserved_event_135",
            Event::ReservedEvent136 => "reserved_event_136",
            Event::ReservedEvent137 => "reserved_event_137",
            Event::ReservedEvent138 => "reserved_event_138",
            Event::ReservedEvent139 => "reserved_event_139",
            Event::ReservedEvent140 => "reserved_event_140",
            Event::ReservedEvent141 => "reserved_event_141",
            Event::ReservedEvent142 => "reserved_event_142",
            Event::ReservedEvent143 => "reserved_event_143",
            Event::ReservedEvent144 => "reserved_event_144",
            Event::ReservedEvent145 => "reserved_event_145",
            Event::ReservedEvent146 => "reserved_event_146",
            Event::ReservedEvent147 => "reserved_event_147",
            Event::ReservedEvent148 => "reserved_event_148",
            Event::ReservedEvent149 => "reserved_event_149",
            Event::ReservedEvent150 => "reserved_event_150",
            Event::ReservedEvent151 => "reserved_event_151",
            Event::ReservedEvent152 => "reserved_event_152",
            Event::ReservedEvent153 => "reserved_event_153",
            Event::ReservedEvent154 => "reserved_event_154",
            Event::ReservedEvent155 => "reserved_event_155",
            Event::ReservedEvent156 => "reserved_event_156",
            Event::ReservedEvent157 => "reserved_event_157",
            Event::ReservedEvent158 => "reserved_event_158",
            Event::ReservedEvent159 => "reserved_event_159",
            Event::ReservedEvent160 => "reserved_event_160",
            Event::ReservedEvent161 => "reserved_event_161",
            Event::EndpointEventBulkBacklogHigh => "endpoint_event_bulk_backlog_high",
            Event::PacketBatchPoolFresh => "packet_batch_pool_fresh",
            Event::PacketBatchPoolReuse => "packet_batch_pool_reuse",
            Event::PacketBatchPoolReturn => "packet_batch_pool_return",
            Event::PacketBatchPoolDiscard => "packet_batch_pool_discard",
            Event::PacketBufferPoolFresh => "packet_buffer_pool_fresh",
            Event::PacketBufferPoolReuse => "packet_buffer_pool_reuse",
            Event::PacketBufferPoolReturn => "packet_buffer_pool_return",
            Event::PacketBufferPoolDiscard => "packet_buffer_pool_discard",
            Event::ReservedEvent171 => "reserved_event_171",
            Event::UdpKernelDropped => "udp_kernel_dropped",
            Event::UdpSocketKernelDropped => "udp_socket_kernel_dropped",
            Event::UdpNamespaceRcvbufErrors => "udp_namespace_rcvbuf_errors",
            Event::ReservedEvent175 => "reserved_event_175",
            Event::ReservedEvent176 => "reserved_event_176",
            Event::ReservedEvent177 => "reserved_event_177",
            Event::ReservedEvent178 => "reserved_event_178",
            Event::ReservedEvent179 => "reserved_event_179",
            Event::ReservedEvent180 => "reserved_event_180",
            Event::ReservedEvent181 => "reserved_event_181",
            Event::ReservedEvent182 => "reserved_event_182",
            Event::ReservedEvent183 => "reserved_event_183",
            Event::ReservedEvent184 => "reserved_event_184",
            Event::ReservedEvent185 => "reserved_event_185",
            Event::TunWriteBulkDropped => "tun_write_bulk_dropped",
            Event::TunWriteBulkBacklogHigh => "tun_write_bulk_backlog_high",
            Event::PacketMover2FspPathOpen => "packet_mover2_fsp_path_open",
            Event::PacketMover2FspPathOpenBulk => "packet_mover2_fsp_path_open_bulk",
            Event::PacketMover2FspOwnerSyncCall => "packet_mover2_fsp_owner_sync_call",
            Event::PacketMover2CryptoOpenBatch => "packet_mover2_crypto_open_batch",
            Event::PacketMover2CryptoOpenPackets => "packet_mover2_crypto_open_packets",
            Event::PacketMover2CryptoSealBatch => "packet_mover2_crypto_seal_batch",
            Event::PacketMover2CryptoSealPackets => "packet_mover2_crypto_seal_packets",
            Event::PacketMover2CryptoBatchSingle => "packet_mover2_crypto_batch_single",
            Event::PacketMover2CryptoBatchGe8 => "packet_mover2_crypto_batch_ge8",
            Event::PacketMover2CryptoBatchGe32 => "packet_mover2_crypto_batch_ge32",
            Event::PacketMover2CryptoBatchGe64 => "packet_mover2_crypto_batch_ge64",
            Event::ReservedEvent199 => "reserved_event_199",
            Event::PacketMover2FspOwnerSyncApplied => "packet_mover2_fsp_owner_sync_applied",
            Event::PacketMover2DispatchOwnerBlocked => "packet_mover2_dispatch_owner_blocked",
            Event::PacketMover2DispatchNoIngress => "packet_mover2_dispatch_no_ingress",
            Event::PacketMover2DispatchLimitHit => "packet_mover2_dispatch_limit_hit",
            Event::PacketMover2DispatchExecutorFull => "packet_mover2_dispatch_executor_full",
            Event::PacketMover2DispatchOwnerBlockedTotal => {
                "packet_mover2_dispatch_owner_blocked_total"
            }
            Event::PacketMover2DispatchOwnerBlockedBulkLane => {
                "packet_mover2_dispatch_owner_blocked_bulk_lane"
            }
            Event::ReservedEvent207 => "reserved_event_207",
            Event::PacketMover2SealInPlace => "packet_mover2_seal_in_place",
            Event::PacketMover2SealAllocated => "packet_mover2_seal_allocated",
            Event::PacketMover2TransportSendWorkerBackpressure => {
                "packet_mover2_transport_send_worker_backpressure"
            }
            Event::PacketMover2TransportSendWorkerDropped => {
                "packet_mover2_transport_send_worker_dropped"
            }
            Event::PacketMover2IngressOwnerRunContinue => {
                "packet_mover2_ingress_owner_run_continue"
            }
            Event::PacketMover2OutboundOwnerRunContinue => {
                "packet_mover2_outbound_owner_run_continue"
            }
            Event::PacketMover2OutboundBatchAdmit => "packet_mover2_outbound_batch_admit",
            Event::PacketMover2OutboundBatchPackets => "packet_mover2_outbound_batch_packets",
            Event::PacketMover2TransportSendWorkerSendFailed => {
                "packet_mover2_transport_send_worker_send_failed"
            }
            Event::ReservedEvent217 => "reserved_event_217",
            Event::ReservedEvent218 => "reserved_event_218",
            Event::ReservedEvent219 => "reserved_event_219",
            Event::ReservedEvent220 => "reserved_event_220",
            Event::PacketMover2LiveRawAdmitted => "packet_mover2_live_raw_admitted",
            Event::PacketMover2LiveEndpointAdmitted => "packet_mover2_live_endpoint_admitted",
            Event::PacketMover2LiveTunAdmitted => "packet_mover2_live_tun_admitted",
            Event::PacketMover2LivePreparedDispatched => "packet_mover2_live_prepared_dispatched",
            Event::PacketMover2LiveCompletionsDrained => "packet_mover2_live_completions_drained",
            Event::PacketMover2LiveRetiredOutputs => "packet_mover2_live_retired_outputs",
            Event::PacketMover2LiveRetiredDrops => "packet_mover2_live_retired_drops",
            Event::PacketMover2LiveOutputDrops => "packet_mover2_live_output_drops",
            Event::PacketMover2AeadOpenInFlight => "packet_mover2_aead_open_in_flight",
            Event::PacketMover2AeadSealInFlight => "packet_mover2_aead_seal_in_flight",
            Event::PacketMover2AeadCompletionQueueDepth => {
                "packet_mover2_aead_completion_queue_depth"
            }
            Event::PacketMover2AeadCompletionBatch => "packet_mover2_aead_completion_batch",
            Event::PacketMover2AeadCompletionBatchPackets => {
                "packet_mover2_aead_completion_batch_packets"
            }
            Event::PacketMover2AeadPreparedJob => "packet_mover2_aead_prepared_job",
            Event::PacketMover2AeadPreparedJobPackets => "packet_mover2_aead_prepared_job_packets",
            Event::PacketMover2LiveCompletionsRetired => "packet_mover2_live_completions_retired",
            Event::PacketMover2LiveOutputBatch => "packet_mover2_live_output_batch",
            Event::PacketMover2LiveOutputBatchPackets => "packet_mover2_live_output_batch_packets",
            Event::PacketMover2AeadOpenQueueDepth => "packet_mover2_aead_open_queue_depth",
            Event::PacketMover2AeadSealQueueDepth => "packet_mover2_aead_seal_queue_depth",
            Event::PacketMover2FastIngressOwnerRuns => "packet_mover2_fast_ingress_owner_runs",
            Event::PacketMover2FastIngressOwnerRunPackets => {
                "packet_mover2_fast_ingress_owner_run_packets"
            }
            Event::PacketMover2EstablishedFspDataRetireRuns => {
                "packet_mover2_established_fsp_data_retire_runs"
            }
            Event::PacketMover2EstablishedFspDataRetirePackets => {
                "packet_mover2_established_fsp_data_retire_packets"
            }
        }
    }
}

fn event_from_index(idx: usize) -> Event {
    match idx {
        0 => Event::ReservedEvent0,
        1 => Event::ReservedEvent1,
        2 => Event::ReservedEvent2,
        3 => Event::ReservedEvent3,
        4 => Event::ReservedEvent4,
        5 => Event::ReservedEvent5,
        6 => Event::ReservedEvent6,
        7 => Event::ReservedEvent7,
        8 => Event::ReservedEvent8,
        9 => Event::ReservedEvent9,
        10 => Event::ReservedEvent10,
        11 => Event::ReservedEvent11,
        12 => Event::ReservedEvent12,
        13 => Event::ReservedEvent13,
        14 => Event::ReservedEvent14,
        15 => Event::ReservedEvent15,
        16 => Event::PendingTunDestinationDropped,
        17 => Event::PendingTunPacketDropped,
        18 => Event::PendingEndpointDestinationDropped,
        19 => Event::PendingEndpointPacketDropped,
        20 => Event::ReservedEvent20,
        21 => Event::EndpointEventBacklogHigh,
        22 => Event::EndpointDataBulkDropped,
        23 => Event::TransportChannelBacklogHigh,
        24 => Event::TransportBulkDropped,
        25 => Event::EndpointEventBulkDropped,
        26 => Event::ReservedEvent26,
        27 => Event::ReservedEvent27,
        28 => Event::ReservedEvent28,
        29 => Event::RxLoopSlowMaintenanceTimeout,
        30 => Event::RxLoopSlowMaintenanceSkipped,
        31 => Event::ReservedEvent31,
        32 => Event::ReservedEvent32,
        33 => Event::ReservedEvent33,
        34 => Event::ReservedEvent34,
        35 => Event::ReservedEvent35,
        36 => Event::ReservedEvent36,
        37 => Event::ReservedEvent37,
        38 => Event::ReservedEvent38,
        39 => Event::ReservedEvent39,
        40 => Event::ReservedEvent40,
        41 => Event::ReservedEvent41,
        42 => Event::ReservedEvent42,
        43 => Event::ReservedEvent43,
        44 => Event::ReservedEvent44,
        45 => Event::ReservedEvent45,
        46 => Event::UdpSendSendmmsgBatch,
        47 => Event::UdpSendSendmmsgPackets,
        48 => Event::UdpSendGsoBatch,
        49 => Event::UdpSendGsoPackets,
        50 => Event::UdpSendGsoBatchGe32,
        51 => Event::UdpSendGsoBatchGe48,
        52 => Event::UdpSendGsoBatchEq64,
        53 => Event::ReservedEvent53,
        54 => Event::ReservedEvent54,
        55 => Event::ReservedEvent55,
        56 => Event::ReservedEvent56,
        57 => Event::UdpSendSendmmsgBatchGe32,
        58 => Event::UdpSendSendmmsgBatchGe48,
        59 => Event::UdpSendSendmmsgBatchEq64,
        60 => Event::ReservedEvent60,
        61 => Event::ReservedEvent61,
        62 => Event::ReservedEvent62,
        63 => Event::ReservedEvent63,
        64 => Event::ReservedEvent64,
        65 => Event::ReservedEvent65,
        66 => Event::ReservedEvent66,
        67 => Event::ReservedEvent67,
        68 => Event::ReservedEvent68,
        69 => Event::ReservedEvent69,
        70 => Event::ReservedEvent70,
        71 => Event::ReservedEvent71,
        72 => Event::ReservedEvent72,
        73 => Event::ReservedEvent73,
        74 => Event::ReservedEvent74,
        75 => Event::ReservedEvent75,
        76 => Event::ReservedEvent76,
        77 => Event::ReservedEvent77,
        78 => Event::ReservedEvent78,
        79 => Event::ReservedEvent79,
        80 => Event::ReservedEvent80,
        81 => Event::ReservedEvent81,
        82 => Event::ReservedEvent82,
        83 => Event::ReservedEvent83,
        84 => Event::ReservedEvent84,
        85 => Event::ReservedEvent85,
        86 => Event::ReservedEvent86,
        87 => Event::ReservedEvent87,
        88 => Event::ReservedEvent88,
        89 => Event::ReservedEvent89,
        90 => Event::ReservedEvent90,
        91 => Event::ReservedEvent91,
        92 => Event::ReservedEvent92,
        93 => Event::ReservedEvent93,
        94 => Event::ReservedEvent94,
        95 => Event::ReservedEvent95,
        96 => Event::ReservedEvent96,
        97 => Event::ReservedEvent97,
        98 => Event::ReservedEvent98,
        99 => Event::ReservedEvent99,
        100 => Event::ReservedEvent100,
        101 => Event::ReservedEvent101,
        102 => Event::ReservedEvent102,
        103 => Event::ReservedEvent103,
        104 => Event::ReservedEvent104,
        105 => Event::ReservedEvent105,
        106 => Event::ReservedEvent106,
        107 => Event::ReservedEvent107,
        108 => Event::ReservedEvent108,
        109 => Event::ReservedEvent109,
        110 => Event::ReservedEvent110,
        111 => Event::ReservedEvent111,
        112 => Event::ReservedEvent112,
        113 => Event::ReservedEvent113,
        114 => Event::ReservedEvent114,
        115 => Event::ReservedEvent115,
        116 => Event::ReservedEvent116,
        117 => Event::ReservedEvent117,
        118 => Event::ReservedEvent118,
        119 => Event::ReservedEvent119,
        120 => Event::ReservedEvent120,
        121 => Event::ReservedEvent121,
        122 => Event::ReservedEvent122,
        123 => Event::ReservedEvent123,
        124 => Event::ReservedEvent124,
        125 => Event::ReservedEvent125,
        126 => Event::ReservedEvent126,
        127 => Event::ReservedEvent127,
        128 => Event::ReservedEvent128,
        129 => Event::ReservedEvent129,
        130 => Event::ReservedEvent130,
        131 => Event::ReservedEvent131,
        132 => Event::ReservedEvent132,
        133 => Event::ReservedEvent133,
        134 => Event::ReservedEvent134,
        135 => Event::ReservedEvent135,
        136 => Event::ReservedEvent136,
        137 => Event::ReservedEvent137,
        138 => Event::ReservedEvent138,
        139 => Event::ReservedEvent139,
        140 => Event::ReservedEvent140,
        141 => Event::ReservedEvent141,
        142 => Event::ReservedEvent142,
        143 => Event::ReservedEvent143,
        144 => Event::ReservedEvent144,
        145 => Event::ReservedEvent145,
        146 => Event::ReservedEvent146,
        147 => Event::ReservedEvent147,
        148 => Event::ReservedEvent148,
        149 => Event::ReservedEvent149,
        150 => Event::ReservedEvent150,
        151 => Event::ReservedEvent151,
        152 => Event::ReservedEvent152,
        153 => Event::ReservedEvent153,
        154 => Event::ReservedEvent154,
        155 => Event::ReservedEvent155,
        156 => Event::ReservedEvent156,
        157 => Event::ReservedEvent157,
        158 => Event::ReservedEvent158,
        159 => Event::ReservedEvent159,
        160 => Event::ReservedEvent160,
        161 => Event::ReservedEvent161,
        162 => Event::EndpointEventBulkBacklogHigh,
        163 => Event::PacketBatchPoolFresh,
        164 => Event::PacketBatchPoolReuse,
        165 => Event::PacketBatchPoolReturn,
        166 => Event::PacketBatchPoolDiscard,
        167 => Event::PacketBufferPoolFresh,
        168 => Event::PacketBufferPoolReuse,
        169 => Event::PacketBufferPoolReturn,
        170 => Event::PacketBufferPoolDiscard,
        171 => Event::ReservedEvent171,
        172 => Event::UdpKernelDropped,
        173 => Event::UdpSocketKernelDropped,
        174 => Event::UdpNamespaceRcvbufErrors,
        175 => Event::ReservedEvent175,
        176 => Event::ReservedEvent176,
        177 => Event::ReservedEvent177,
        178 => Event::ReservedEvent178,
        179 => Event::ReservedEvent179,
        180 => Event::ReservedEvent180,
        181 => Event::ReservedEvent181,
        182 => Event::ReservedEvent182,
        183 => Event::ReservedEvent183,
        184 => Event::ReservedEvent184,
        185 => Event::ReservedEvent185,
        186 => Event::TunWriteBulkDropped,
        187 => Event::TunWriteBulkBacklogHigh,
        188 => Event::PacketMover2FspPathOpen,
        189 => Event::PacketMover2FspPathOpenBulk,
        190 => Event::PacketMover2FspOwnerSyncCall,
        191 => Event::PacketMover2CryptoOpenBatch,
        192 => Event::PacketMover2CryptoOpenPackets,
        193 => Event::PacketMover2CryptoSealBatch,
        194 => Event::PacketMover2CryptoSealPackets,
        195 => Event::PacketMover2CryptoBatchSingle,
        196 => Event::PacketMover2CryptoBatchGe8,
        197 => Event::PacketMover2CryptoBatchGe32,
        198 => Event::PacketMover2CryptoBatchGe64,
        199 => Event::ReservedEvent199,
        200 => Event::PacketMover2FspOwnerSyncApplied,
        201 => Event::PacketMover2DispatchOwnerBlocked,
        202 => Event::PacketMover2DispatchNoIngress,
        203 => Event::PacketMover2DispatchLimitHit,
        204 => Event::PacketMover2DispatchExecutorFull,
        205 => Event::PacketMover2DispatchOwnerBlockedTotal,
        206 => Event::PacketMover2DispatchOwnerBlockedBulkLane,
        207 => Event::ReservedEvent207,
        208 => Event::PacketMover2SealInPlace,
        209 => Event::PacketMover2SealAllocated,
        210 => Event::PacketMover2TransportSendWorkerBackpressure,
        211 => Event::PacketMover2TransportSendWorkerDropped,
        212 => Event::PacketMover2IngressOwnerRunContinue,
        213 => Event::PacketMover2OutboundOwnerRunContinue,
        214 => Event::PacketMover2OutboundBatchAdmit,
        215 => Event::PacketMover2OutboundBatchPackets,
        216 => Event::PacketMover2TransportSendWorkerSendFailed,
        217 => Event::ReservedEvent217,
        218 => Event::ReservedEvent218,
        219 => Event::ReservedEvent219,
        220 => Event::ReservedEvent220,
        221 => Event::PacketMover2LiveRawAdmitted,
        222 => Event::PacketMover2LiveEndpointAdmitted,
        223 => Event::PacketMover2LiveTunAdmitted,
        224 => Event::PacketMover2LivePreparedDispatched,
        225 => Event::PacketMover2LiveCompletionsDrained,
        226 => Event::PacketMover2LiveRetiredOutputs,
        227 => Event::PacketMover2LiveRetiredDrops,
        228 => Event::PacketMover2LiveOutputDrops,
        229 => Event::PacketMover2AeadOpenInFlight,
        230 => Event::PacketMover2AeadSealInFlight,
        231 => Event::PacketMover2AeadCompletionQueueDepth,
        232 => Event::PacketMover2AeadCompletionBatch,
        233 => Event::PacketMover2AeadCompletionBatchPackets,
        234 => Event::PacketMover2AeadPreparedJob,
        235 => Event::PacketMover2AeadPreparedJobPackets,
        236 => Event::PacketMover2LiveCompletionsRetired,
        237 => Event::PacketMover2LiveOutputBatch,
        238 => Event::PacketMover2LiveOutputBatchPackets,
        239 => Event::PacketMover2AeadOpenQueueDepth,
        240 => Event::PacketMover2AeadSealQueueDepth,
        241 => Event::PacketMover2FastIngressOwnerRuns,
        242 => Event::PacketMover2FastIngressOwnerRunPackets,
        243 => Event::PacketMover2EstablishedFspDataRetireRuns,
        244 => Event::PacketMover2EstablishedFspDataRetirePackets,
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

#[inline]
pub(crate) fn record_since(stage: Stage, start: Option<TraceStamp>) {
    if !enabled() {
        return;
    }
    let Some(start) = start else {
        return;
    };
    record_count(stage, start.elapsed_ns().max(1), 1);
}

#[inline]
pub(crate) fn record_since_count(stage: Stage, start: Option<TraceStamp>, count: u64) {
    if !enabled() || count == 0 {
        return;
    }
    let Some(start) = start else {
        return;
    };
    record_count(stage, start.elapsed_ns().max(1), count);
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

/// Record the prepared PM2 open chunk width before inline AEAD execution.
///
/// These counters describe the natural work unit available to a future
/// stateless crypto worker pool. They stay trace-gated and do not imply a
/// second packet path.
#[inline]
pub(crate) fn record_packet_mover2_crypto_open_batch(packets: usize) {
    record_packet_mover2_crypto_batch(
        Event::PacketMover2CryptoOpenBatch,
        Event::PacketMover2CryptoOpenPackets,
        packets,
    );
}

/// Record the prepared PM2 seal chunk width before inline AEAD execution.
#[inline]
pub(crate) fn record_packet_mover2_crypto_seal_batch(packets: usize) {
    record_packet_mover2_crypto_batch(
        Event::PacketMover2CryptoSealBatch,
        Event::PacketMover2CryptoSealPackets,
        packets,
    );
}

#[inline]
fn record_packet_mover2_crypto_batch(batch_event: Event, packet_event: Event, packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(batch_event, 1);
    record_event_count_sample(packet_event, packets as u64);
    let (single, ge8, ge32, ge64) = packet_mover2_crypto_batch_bucket_flags(packets);
    if single {
        record_event_count_sample(Event::PacketMover2CryptoBatchSingle, 1);
    }
    if ge8 {
        record_event_count_sample(Event::PacketMover2CryptoBatchGe8, 1);
    }
    if ge32 {
        record_event_count_sample(Event::PacketMover2CryptoBatchGe32, 1);
    }
    if ge64 {
        record_event_count_sample(Event::PacketMover2CryptoBatchGe64, 1);
    }
}

#[inline]
fn packet_mover2_crypto_batch_bucket_flags(packets: usize) -> (bool, bool, bool, bool) {
    (packets == 1, packets >= 8, packets >= 32, packets >= 64)
}

#[inline]
pub(crate) fn record_packet_mover2_aead_completion_batch(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::PacketMover2AeadCompletionBatch, 1);
    record_event_count_sample(
        Event::PacketMover2AeadCompletionBatchPackets,
        packets as u64,
    );
}

#[inline]
pub(crate) fn record_packet_mover2_aead_prepared_job(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::PacketMover2AeadPreparedJob, 1);
    record_event_count_sample(Event::PacketMover2AeadPreparedJobPackets, packets as u64);
}

#[inline]
pub(crate) fn record_packet_mover2_fast_ingress_owner_run(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::PacketMover2FastIngressOwnerRuns, 1);
    record_event_count_sample(
        Event::PacketMover2FastIngressOwnerRunPackets,
        packets as u64,
    );
}

#[inline]
pub(crate) fn record_packet_mover2_established_fsp_data_retire_run(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::PacketMover2EstablishedFspDataRetireRuns, 1);
    record_event_count_sample(
        Event::PacketMover2EstablishedFspDataRetirePackets,
        packets as u64,
    );
}

#[inline]
pub(crate) fn record_packet_mover2_live_completions_retired(count: usize) {
    record_event_count(Event::PacketMover2LiveCompletionsRetired, count as u64);
}

#[inline]
pub(crate) fn record_packet_mover2_live_output_batch(packets: usize) {
    if !enabled() || packets == 0 {
        return;
    }
    record_event_count_sample(Event::PacketMover2LiveOutputBatch, 1);
    record_event_count_sample(Event::PacketMover2LiveOutputBatchPackets, packets as u64);
}

#[inline]
#[cfg(test)]
fn record_wait_threshold(event: Event, elapsed_ns: u64, count: u64, threshold_ns: u64) {
    if elapsed_ns >= threshold_ns {
        record_event_count_sample(event, count);
    }
}

/// Record Linux `sendmmsg(2)` UDP batches submitted by the PM2 send side.

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

/// Record Linux `sendmsg(2)+UDP_SEGMENT` batches submitted by the PM2 send side.
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

/// RAII timer - `drop` records the elapsed time into the stage.
/// Use:
/// ```ignore
/// let _t = profile::Timer::start(Stage::PacketMover2AeadOpen);
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
