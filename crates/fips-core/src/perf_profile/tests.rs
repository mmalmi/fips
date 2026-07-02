#[cfg(target_os = "linux")]
use super::udp_send_batch_tail_bucket_flags;
use super::{
    EVENTS, Event, HIST_BUCKETS, N_EVENTS, N_STAGES, Stage, TraceStamp, bucket_upper_ns,
    event_from_index, fmt_rate_per_sec, packet_mover2_crypto_batch_bucket_flags, percentile_ns,
    record_event_count_sample, record_wait_threshold, stage_from_index,
};
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

#[test]
fn trace_stamp_is_compact_for_hot_queue_records() {
    assert_eq!(std::mem::size_of::<Option<TraceStamp>>(), 8);
    assert!(std::mem::size_of::<Option<TraceStamp>>() < std::mem::size_of::<Option<Instant>>());
}

#[test]
fn reporter_rate_format_preserves_sub_one_hz_samples() {
    assert_eq!(fmt_rate_per_sec(10, 5), "2");
    assert_eq!(fmt_rate_per_sec(1, 5), "0.2");
    assert_eq!(fmt_rate_per_sec(1, 60), "0.017");
    assert_eq!(fmt_rate_per_sec(1_234_567, 10), "123456.7");
}

#[test]
fn percentile_uses_observed_histogram_count_when_stage_count_leads() {
    let mut hist = [0u64; HIST_BUCKETS];
    hist[10] = 1;

    assert_eq!(percentile_ns(&hist, 2, 99), bucket_upper_ns(10));
    assert_eq!(percentile_ns(&[0u64; HIST_BUCKETS], 1, 99), 0);
}

#[test]
fn event_table_exposes_current_pm2_and_queue_events() {
    assert_eq!(N_EVENTS, 245);
    assert!(
        (Event::PacketMover2EstablishedFspDataRetirePackets as usize) < N_EVENTS,
        "last event must fit in the EVENTS table"
    );

    let live_events = [
        (
            Event::PendingTunDestinationDropped,
            "pending_tun_destination_dropped",
        ),
        (Event::PendingTunPacketDropped, "pending_tun_packet_dropped"),
        (
            Event::PendingEndpointDestinationDropped,
            "pending_endpoint_destination_dropped",
        ),
        (
            Event::PendingEndpointPacketDropped,
            "pending_endpoint_packet_dropped",
        ),
        (
            Event::EndpointEventBacklogHigh,
            "endpoint_event_backlog_high",
        ),
        (
            Event::EndpointEventBulkBacklogHigh,
            "endpoint_event_bulk_backlog_high",
        ),
        (Event::EndpointDataBulkDropped, "endpoint_data_bulk_dropped"),
        (
            Event::TransportChannelBacklogHigh,
            "transport_channel_backlog_high",
        ),
        (Event::TransportBulkDropped, "transport_bulk_dropped"),
        (
            Event::EndpointEventBulkDropped,
            "endpoint_event_bulk_dropped",
        ),
        (
            Event::RxLoopSlowMaintenanceTimeout,
            "rx_loop_slow_maintenance_timeout",
        ),
        (
            Event::RxLoopSlowMaintenanceSkipped,
            "rx_loop_slow_maintenance_skipped",
        ),
        (Event::UdpSendSendmmsgBatch, "udp_send_sendmmsg_batch"),
        (Event::UdpSendSendmmsgPackets, "udp_send_sendmmsg_packets"),
        (Event::UdpSendGsoBatch, "udp_send_gso_batch"),
        (Event::UdpSendGsoPackets, "udp_send_gso_packets"),
        (Event::UdpSendGsoBatchGe32, "udp_send_gso_batch_ge32"),
        (Event::UdpSendGsoBatchGe48, "udp_send_gso_batch_ge48"),
        (Event::UdpSendGsoBatchEq64, "udp_send_gso_batch_eq64"),
        (
            Event::UdpSendSendmmsgBatchGe32,
            "udp_send_sendmmsg_batch_ge32",
        ),
        (
            Event::UdpSendSendmmsgBatchGe48,
            "udp_send_sendmmsg_batch_ge48",
        ),
        (
            Event::UdpSendSendmmsgBatchEq64,
            "udp_send_sendmmsg_batch_eq64",
        ),
        (Event::PacketBatchPoolFresh, "packet_batch_pool_fresh"),
        (Event::PacketBatchPoolReuse, "packet_batch_pool_reuse"),
        (Event::PacketBatchPoolReturn, "packet_batch_pool_return"),
        (Event::PacketBatchPoolDiscard, "packet_batch_pool_discard"),
        (Event::PacketBufferPoolFresh, "packet_buffer_pool_fresh"),
        (Event::PacketBufferPoolReuse, "packet_buffer_pool_reuse"),
        (Event::PacketBufferPoolReturn, "packet_buffer_pool_return"),
        (Event::PacketBufferPoolDiscard, "packet_buffer_pool_discard"),
        (Event::UdpKernelDropped, "udp_kernel_dropped"),
        (Event::UdpSocketKernelDropped, "udp_socket_kernel_dropped"),
        (
            Event::UdpNamespaceRcvbufErrors,
            "udp_namespace_rcvbuf_errors",
        ),
        (Event::TunWriteBulkDropped, "tun_write_bulk_dropped"),
        (
            Event::TunWriteBulkBacklogHigh,
            "tun_write_bulk_backlog_high",
        ),
        (
            Event::PacketMover2FspPathOpen,
            "packet_mover2_fsp_path_open",
        ),
        (
            Event::PacketMover2FspPathOpenBulk,
            "packet_mover2_fsp_path_open_bulk",
        ),
        (
            Event::PacketMover2FspOwnerSyncCall,
            "packet_mover2_fsp_owner_sync_call",
        ),
        (
            Event::PacketMover2CryptoOpenBatch,
            "packet_mover2_crypto_open_batch",
        ),
        (
            Event::PacketMover2CryptoOpenPackets,
            "packet_mover2_crypto_open_packets",
        ),
        (
            Event::PacketMover2CryptoSealBatch,
            "packet_mover2_crypto_seal_batch",
        ),
        (
            Event::PacketMover2CryptoSealPackets,
            "packet_mover2_crypto_seal_packets",
        ),
        (
            Event::PacketMover2CryptoBatchSingle,
            "packet_mover2_crypto_batch_single",
        ),
        (
            Event::PacketMover2CryptoBatchGe8,
            "packet_mover2_crypto_batch_ge8",
        ),
        (
            Event::PacketMover2CryptoBatchGe32,
            "packet_mover2_crypto_batch_ge32",
        ),
        (
            Event::PacketMover2CryptoBatchGe64,
            "packet_mover2_crypto_batch_ge64",
        ),
        (Event::ReservedEvent199, "reserved_event_199"),
        (
            Event::PacketMover2FspOwnerSyncApplied,
            "packet_mover2_fsp_owner_sync_applied",
        ),
        (
            Event::PacketMover2DispatchOwnerBlocked,
            "packet_mover2_dispatch_owner_blocked",
        ),
        (
            Event::PacketMover2DispatchNoIngress,
            "packet_mover2_dispatch_no_ingress",
        ),
        (
            Event::PacketMover2DispatchLimitHit,
            "packet_mover2_dispatch_limit_hit",
        ),
        (
            Event::PacketMover2DispatchExecutorFull,
            "packet_mover2_dispatch_executor_full",
        ),
        (
            Event::PacketMover2DispatchOwnerBlockedTotal,
            "packet_mover2_dispatch_owner_blocked_total",
        ),
        (
            Event::PacketMover2DispatchOwnerBlockedBulkLane,
            "packet_mover2_dispatch_owner_blocked_bulk_lane",
        ),
        (
            Event::PacketMover2TransportSendWorkerBackpressure,
            "packet_mover2_transport_send_worker_backpressure",
        ),
        (
            Event::PacketMover2TransportSendWorkerDropped,
            "packet_mover2_transport_send_worker_dropped",
        ),
        (
            Event::PacketMover2TransportSendWorkerSendFailed,
            "packet_mover2_transport_send_worker_send_failed",
        ),
        (
            Event::PacketMover2LiveRawAdmitted,
            "packet_mover2_live_raw_admitted",
        ),
        (
            Event::PacketMover2LiveEndpointAdmitted,
            "packet_mover2_live_endpoint_admitted",
        ),
        (
            Event::PacketMover2LiveTunAdmitted,
            "packet_mover2_live_tun_admitted",
        ),
        (
            Event::PacketMover2LivePreparedDispatched,
            "packet_mover2_live_prepared_dispatched",
        ),
        (
            Event::PacketMover2LiveCompletionsDrained,
            "packet_mover2_live_completions_drained",
        ),
        (
            Event::PacketMover2LiveRetiredOutputs,
            "packet_mover2_live_retired_outputs",
        ),
        (
            Event::PacketMover2LiveRetiredDrops,
            "packet_mover2_live_retired_drops",
        ),
        (
            Event::PacketMover2LiveOutputDrops,
            "packet_mover2_live_output_drops",
        ),
        (
            Event::PacketMover2AeadOpenInFlight,
            "packet_mover2_aead_open_in_flight",
        ),
        (
            Event::PacketMover2AeadSealInFlight,
            "packet_mover2_aead_seal_in_flight",
        ),
        (
            Event::PacketMover2AeadCompletionQueueDepth,
            "packet_mover2_aead_completion_queue_depth",
        ),
        (
            Event::PacketMover2AeadCompletionBatch,
            "packet_mover2_aead_completion_batch",
        ),
        (
            Event::PacketMover2AeadCompletionBatchPackets,
            "packet_mover2_aead_completion_batch_packets",
        ),
        (
            Event::PacketMover2AeadPreparedJob,
            "packet_mover2_aead_prepared_job",
        ),
        (
            Event::PacketMover2AeadPreparedJobPackets,
            "packet_mover2_aead_prepared_job_packets",
        ),
        (
            Event::PacketMover2LiveCompletionsRetired,
            "packet_mover2_live_completions_retired",
        ),
        (
            Event::PacketMover2LiveOutputBatch,
            "packet_mover2_live_output_batch",
        ),
        (
            Event::PacketMover2LiveOutputBatchPackets,
            "packet_mover2_live_output_batch_packets",
        ),
        (
            Event::PacketMover2AeadOpenQueueDepth,
            "packet_mover2_aead_open_queue_depth",
        ),
        (
            Event::PacketMover2AeadSealQueueDepth,
            "packet_mover2_aead_seal_queue_depth",
        ),
        (
            Event::PacketMover2FastIngressOwnerRuns,
            "packet_mover2_fast_ingress_owner_runs",
        ),
        (
            Event::PacketMover2FastIngressOwnerRunPackets,
            "packet_mover2_fast_ingress_owner_run_packets",
        ),
        (
            Event::PacketMover2EstablishedFspDataRetireRuns,
            "packet_mover2_established_fsp_data_retire_runs",
        ),
        (
            Event::PacketMover2EstablishedFspDataRetirePackets,
            "packet_mover2_established_fsp_data_retire_packets",
        ),
    ];
    for (event, name) in live_events {
        assert_eq!(event_from_index(event as usize).name(), name);
    }

    for (event, name) in [
        (Event::ReservedEvent0, "reserved_event_0"),
        (Event::ReservedEvent7, "reserved_event_7"),
        (Event::ReservedEvent38, "reserved_event_38"),
        (Event::ReservedEvent70, "reserved_event_70"),
        (Event::ReservedEvent75, "reserved_event_75"),
        (Event::ReservedEvent96, "reserved_event_96"),
        (Event::ReservedEvent108, "reserved_event_108"),
        (Event::ReservedEvent171, "reserved_event_171"),
        (Event::ReservedEvent219, "reserved_event_219"),
        (Event::ReservedEvent220, "reserved_event_220"),
    ] {
        assert_eq!(event_from_index(event as usize).name(), name);
    }
}

#[test]
#[cfg(target_os = "linux")]
fn udp_send_batch_buckets_classify_large_bursts() {
    assert_eq!(udp_send_batch_tail_bucket_flags(0), (false, false, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(31), (false, false, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(32), (true, false, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(47), (true, false, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(48), (true, true, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(63), (true, true, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(64), (true, true, true));
}

#[test]
fn packet_mover2_crypto_batch_buckets_classify_worker_chunks() {
    assert_eq!(
        packet_mover2_crypto_batch_bucket_flags(0),
        (false, false, false, false)
    );
    assert_eq!(
        packet_mover2_crypto_batch_bucket_flags(1),
        (true, false, false, false)
    );
    assert_eq!(
        packet_mover2_crypto_batch_bucket_flags(7),
        (false, false, false, false)
    );
    assert_eq!(
        packet_mover2_crypto_batch_bucket_flags(8),
        (false, true, false, false)
    );
    assert_eq!(
        packet_mover2_crypto_batch_bucket_flags(31),
        (false, true, false, false)
    );
    assert_eq!(
        packet_mover2_crypto_batch_bucket_flags(32),
        (false, true, true, false)
    );
    assert_eq!(
        packet_mover2_crypto_batch_bucket_flags(64),
        (false, true, true, true)
    );
}

#[test]
fn stage_table_exposes_current_pm2_transport_and_output_stages() {
    assert_eq!(N_STAGES, 69);

    for (stage, name) in [
        (Stage::UdpRecv, "udp_recv"),
        (Stage::TunWrite, "tun_write"),
        (Stage::UdpSend, "udp_send"),
        (Stage::EndpointDeliver, "endpoint_deliver"),
        (Stage::EndpointEventWait, "endpoint_event_wait"),
        (Stage::ReservedStage18, "reserved_stage_18"),
        (Stage::ReservedStage19, "reserved_stage_19"),
        (Stage::TransportChannelWait, "transport_channel_wait"),
        (
            Stage::TransportPriorityChannelWait,
            "transport_priority_channel_wait",
        ),
        (
            Stage::TransportBulkChannelWait,
            "transport_bulk_channel_wait",
        ),
        (
            Stage::TransportRxLoopOwnedWait,
            "transport_rx_loop_owned_wait",
        ),
        (Stage::PacketMover2AeadOpen, "packet_mover2_aead_open"),
        (Stage::PacketMover2AeadSeal, "packet_mover2_aead_seal"),
        (Stage::PacketMover2Retire, "packet_mover2_retire"),
        (
            Stage::PacketMover2FspOwnerSync,
            "packet_mover2_fsp_owner_sync",
        ),
        (Stage::PacketMover2LiveTurn, "packet_mover2_live_turn"),
        (
            Stage::PacketMover2CompletionDrain,
            "packet_mover2_completion_drain",
        ),
        (Stage::PacketMover2LiveAdmit, "packet_mover2_live_admit"),
        (
            Stage::PacketMover2AeadDispatch,
            "packet_mover2_aead_dispatch",
        ),
        (Stage::PacketMover2OutputSink, "packet_mover2_output_sink"),
        (
            Stage::PacketMover2TransportSend,
            "packet_mover2_transport_send",
        ),
        (
            Stage::PacketMover2TransportSendWorker,
            "packet_mover2_transport_send_worker",
        ),
        (
            Stage::PacketMover2OwnerDispatch,
            "packet_mover2_owner_dispatch",
        ),
        (
            Stage::PacketMover2ExecutorSubmit,
            "packet_mover2_executor_submit",
        ),
        (
            Stage::PacketMover2CompletionQueue,
            "packet_mover2_completion_queue",
        ),
        (
            Stage::PacketMover2AeadWorkerQueueWait,
            "packet_mover2_aead_worker_queue_wait",
        ),
    ] {
        assert_eq!(stage_from_index(stage as usize).name(), name);
    }

    for (stage, name) in [
        (Stage::ReservedStage1, "reserved_stage_1"),
        (Stage::ReservedStage3, "reserved_stage_3"),
        (Stage::ReservedStage11, "reserved_stage_11"),
        (Stage::ReservedStage13, "reserved_stage_13"),
        (Stage::ReservedStage24, "reserved_stage_24"),
        (Stage::ReservedStage29, "reserved_stage_29"),
        (Stage::ReservedStage34, "reserved_stage_34"),
        (Stage::ReservedStage37, "reserved_stage_37"),
        (Stage::ReservedStage47, "reserved_stage_47"),
        (Stage::ReservedStage52, "reserved_stage_52"),
        (Stage::ReservedStage68, "reserved_stage_68"),
    ] {
        assert_eq!(stage_from_index(stage as usize).name(), name);
    }
}

#[test]
fn live_event_counters_increment() {
    let samples = [
        (Event::RxLoopSlowMaintenanceTimeout, 3),
        (Event::RxLoopSlowMaintenanceSkipped, 5),
        (Event::EndpointEventBacklogHigh, 7),
        (Event::EndpointEventBulkBacklogHigh, 11),
        (Event::EndpointEventBulkDropped, 13),
        (Event::EndpointDataBulkDropped, 17),
        (Event::TransportChannelBacklogHigh, 19),
        (Event::TransportBulkDropped, 23),
        (Event::PendingTunPacketDropped, 29),
        (Event::PendingEndpointPacketDropped, 31),
        (Event::UdpSendSendmmsgBatch, 37),
        (Event::UdpSendSendmmsgPackets, 41),
        (Event::UdpSendSendmmsgBatchGe32, 43),
        (Event::PacketMover2FspPathOpen, 47),
        (Event::PacketMover2FspPathOpenBulk, 53),
        (Event::PacketMover2FspOwnerSyncCall, 57),
        (Event::PacketMover2CryptoOpenBatch, 59),
        (Event::PacketMover2CryptoSealPackets, 61),
        (Event::ReservedEvent199, 63),
        (Event::PacketMover2FspOwnerSyncApplied, 65),
        (Event::PacketBatchPoolReuse, 67),
        (Event::PacketBufferPoolFresh, 71),
        (Event::UdpKernelDropped, 73),
        (Event::UdpSocketKernelDropped, 79),
        (Event::UdpNamespaceRcvbufErrors, 83),
        (Event::TunWriteBulkDropped, 89),
        (Event::TunWriteBulkBacklogHigh, 97),
        (Event::PacketMover2TransportSendWorkerBackpressure, 101),
        (Event::PacketMover2TransportSendWorkerDropped, 103),
        (Event::PacketMover2TransportSendWorkerSendFailed, 107),
    ];

    for (event, count) in samples {
        let before = EVENTS[event as usize].load(Relaxed);
        record_event_count_sample(event, count);
        assert_eq!(EVENTS[event as usize].load(Relaxed) - before, count);
    }
}

#[test]
fn wait_threshold_events_only_count_samples_at_or_above_threshold() {
    let event = Event::EndpointEventBacklogHigh;
    let before = EVENTS[event as usize].load(Relaxed);

    record_wait_threshold(event, 499_999, 3, 500_000);
    record_wait_threshold(event, 500_000, 5, 500_000);
    record_wait_threshold(event, 750_000, 7, 500_000);

    assert_eq!(EVENTS[event as usize].load(Relaxed) - before, 12);
}
