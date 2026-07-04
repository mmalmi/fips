#[cfg(target_os = "linux")]
use super::udp_send_batch_tail_bucket_flags;
use super::{
    EVENTS, Event, HIST_BUCKETS, N_EVENTS, N_STAGES, Stage, TraceStamp, bucket_upper_ns,
    dataplane_crypto_batch_bucket_flags, event_from_index, fmt_rate_per_sec, percentile_ns,
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
fn event_table_exposes_current_dataplane_and_queue_events() {
    assert_eq!(N_EVENTS, 245);
    assert!(
        (Event::DataplaneEstablishedFspDataRetirePackets as usize) < N_EVENTS,
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
        (Event::UdpRecvGroBatch, "udp_recv_gro_batch"),
        (Event::UdpRecvGroPackets, "udp_recv_gro_packets"),
        (Event::UdpRecvGroBytes, "udp_recv_gro_bytes"),
        (Event::UdpRecvPlainPackets, "udp_recv_plain_packets"),
        (Event::TunReadPackets, "tun_read_packets"),
        (Event::TunReadBytes, "tun_read_bytes"),
        (Event::TunWritePackets, "tun_write_packets"),
        (Event::TunWriteBytes, "tun_write_bytes"),
        (Event::TunReadFrames, "tun_read_frames"),
        (Event::TunReadFrameBytes, "tun_read_frame_bytes"),
        (Event::TunWriteFrames, "tun_write_frames"),
        (Event::TunWriteFrameBytes, "tun_write_frame_bytes"),
        (
            Event::TunOutboundAdmissionDropped,
            "tun_outbound_admission_dropped",
        ),
        (
            Event::PendingTunSessionOldestDropped,
            "pending_tun_session_oldest_dropped",
        ),
        (
            Event::PendingTunSessionStaleDropped,
            "pending_tun_session_stale_dropped",
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
        (Event::DataplaneFspPathOpen, "dataplane_fsp_path_open"),
        (
            Event::DataplaneFspPathOpenBulk,
            "dataplane_fsp_path_open_bulk",
        ),
        (
            Event::DataplaneFspOwnerSyncCall,
            "dataplane_fsp_owner_sync_call",
        ),
        (
            Event::DataplaneCryptoOpenBatch,
            "dataplane_crypto_open_batch",
        ),
        (
            Event::DataplaneCryptoOpenPackets,
            "dataplane_crypto_open_packets",
        ),
        (
            Event::DataplaneCryptoSealBatch,
            "dataplane_crypto_seal_batch",
        ),
        (
            Event::DataplaneCryptoSealPackets,
            "dataplane_crypto_seal_packets",
        ),
        (
            Event::DataplaneCryptoBatchSingle,
            "dataplane_crypto_batch_single",
        ),
        (Event::DataplaneCryptoBatchGe8, "dataplane_crypto_batch_ge8"),
        (
            Event::DataplaneCryptoBatchGe32,
            "dataplane_crypto_batch_ge32",
        ),
        (
            Event::DataplaneCryptoBatchGe64,
            "dataplane_crypto_batch_ge64",
        ),
        (Event::ReservedEvent199, "reserved_event_199"),
        (
            Event::DataplaneFspOwnerSyncApplied,
            "dataplane_fsp_owner_sync_applied",
        ),
        (
            Event::DataplaneDispatchOwnerBlocked,
            "dataplane_dispatch_owner_blocked",
        ),
        (
            Event::DataplaneDispatchNoIngress,
            "dataplane_dispatch_no_ingress",
        ),
        (
            Event::DataplaneDispatchLimitHit,
            "dataplane_dispatch_limit_hit",
        ),
        (
            Event::DataplaneDispatchExecutorFull,
            "dataplane_dispatch_executor_full",
        ),
        (
            Event::DataplaneDispatchOwnerBlockedTotal,
            "dataplane_dispatch_owner_blocked_total",
        ),
        (
            Event::DataplaneDispatchOwnerBlockedBulkLane,
            "dataplane_dispatch_owner_blocked_bulk_lane",
        ),
        (
            Event::DataplaneDispatchIngressOwnerBlocked,
            "dataplane_dispatch_ingress_owner_blocked",
        ),
        (
            Event::DataplaneDispatchOutboundOwnerBlocked,
            "dataplane_dispatch_outbound_owner_blocked",
        ),
        (
            Event::DataplaneTransportSendWorkerBackpressure,
            "dataplane_transport_send_worker_backpressure",
        ),
        (
            Event::DataplaneTransportSendWorkerDropped,
            "dataplane_transport_send_worker_dropped",
        ),
        (
            Event::DataplaneTransportSendWorkerSendFailed,
            "dataplane_transport_send_worker_send_failed",
        ),
        (
            Event::DataplaneLiveRawAdmitted,
            "dataplane_live_raw_admitted",
        ),
        (
            Event::DataplaneLiveEndpointAdmitted,
            "dataplane_live_endpoint_admitted",
        ),
        (
            Event::DataplaneLiveTunAdmitted,
            "dataplane_live_tun_admitted",
        ),
        (
            Event::DataplaneLivePreparedDispatched,
            "dataplane_live_prepared_dispatched",
        ),
        (
            Event::DataplaneLiveCompletionsDrained,
            "dataplane_live_completions_drained",
        ),
        (
            Event::DataplaneLiveRetiredOutputs,
            "dataplane_live_retired_outputs",
        ),
        (
            Event::DataplaneLiveRetiredDrops,
            "dataplane_live_retired_drops",
        ),
        (
            Event::DataplaneLiveOutputDrops,
            "dataplane_live_output_drops",
        ),
        (
            Event::DataplaneAeadOpenInFlight,
            "dataplane_aead_open_in_flight",
        ),
        (
            Event::DataplaneAeadSealInFlight,
            "dataplane_aead_seal_in_flight",
        ),
        (
            Event::DataplaneAeadCompletionQueueDepth,
            "dataplane_aead_completion_queue_depth",
        ),
        (
            Event::DataplaneAeadCompletionBatch,
            "dataplane_aead_completion_batch",
        ),
        (
            Event::DataplaneAeadCompletionBatchPackets,
            "dataplane_aead_completion_batch_packets",
        ),
        (
            Event::DataplaneAeadPreparedJob,
            "dataplane_aead_prepared_job",
        ),
        (
            Event::DataplaneAeadPreparedJobPackets,
            "dataplane_aead_prepared_job_packets",
        ),
        (
            Event::DataplaneLiveCompletionsRetired,
            "dataplane_live_completions_retired",
        ),
        (
            Event::DataplaneLiveOutputBatch,
            "dataplane_live_output_batch",
        ),
        (
            Event::DataplaneLiveOutputBatchPackets,
            "dataplane_live_output_batch_packets",
        ),
        (
            Event::DataplaneAeadOpenQueueDepth,
            "dataplane_aead_open_queue_depth",
        ),
        (
            Event::DataplaneAeadSealQueueDepth,
            "dataplane_aead_seal_queue_depth",
        ),
        (
            Event::DataplaneFastIngressOwnerRuns,
            "dataplane_fast_ingress_owner_runs",
        ),
        (
            Event::DataplaneFastIngressOwnerRunPackets,
            "dataplane_fast_ingress_owner_run_packets",
        ),
        (
            Event::DataplaneEstablishedFspDataRetireRuns,
            "dataplane_established_fsp_data_retire_runs",
        ),
        (
            Event::DataplaneEstablishedFspDataRetirePackets,
            "dataplane_established_fsp_data_retire_packets",
        ),
    ];
    for (event, name) in live_events {
        assert_eq!(event_from_index(event as usize).name(), name);
    }

    for (event, name) in [
        (Event::ReservedEvent0, "reserved_event_0"),
        (Event::ReservedEvent7, "reserved_event_7"),
        (Event::ReservedEvent38, "reserved_event_38"),
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
fn dataplane_crypto_batch_buckets_classify_worker_chunks() {
    assert_eq!(
        dataplane_crypto_batch_bucket_flags(0),
        (false, false, false, false)
    );
    assert_eq!(
        dataplane_crypto_batch_bucket_flags(1),
        (true, false, false, false)
    );
    assert_eq!(
        dataplane_crypto_batch_bucket_flags(7),
        (false, false, false, false)
    );
    assert_eq!(
        dataplane_crypto_batch_bucket_flags(8),
        (false, true, false, false)
    );
    assert_eq!(
        dataplane_crypto_batch_bucket_flags(31),
        (false, true, false, false)
    );
    assert_eq!(
        dataplane_crypto_batch_bucket_flags(32),
        (false, true, true, false)
    );
    assert_eq!(
        dataplane_crypto_batch_bucket_flags(64),
        (false, true, true, true)
    );
}

#[test]
fn stage_table_exposes_current_dataplane_transport_and_output_stages() {
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
        (Stage::DataplaneAeadOpen, "dataplane_aead_open"),
        (Stage::DataplaneAeadSeal, "dataplane_aead_seal"),
        (Stage::DataplaneRetire, "dataplane_retire"),
        (Stage::DataplaneFspOwnerSync, "dataplane_fsp_owner_sync"),
        (Stage::DataplaneLiveTurn, "dataplane_live_turn"),
        (
            Stage::DataplaneCompletionDrain,
            "dataplane_completion_drain",
        ),
        (Stage::DataplaneLiveAdmit, "dataplane_live_admit"),
        (Stage::DataplaneAeadDispatch, "dataplane_aead_dispatch"),
        (Stage::DataplaneOutputSink, "dataplane_output_sink"),
        (Stage::DataplaneTransportSend, "dataplane_transport_send"),
        (
            Stage::DataplaneTransportSendWorker,
            "dataplane_transport_send_worker",
        ),
        (Stage::DataplaneOwnerDispatch, "dataplane_owner_dispatch"),
        (Stage::DataplaneExecutorSubmit, "dataplane_executor_submit"),
        (
            Stage::DataplaneCompletionQueue,
            "dataplane_completion_queue",
        ),
        (
            Stage::DataplaneAeadWorkerQueueWait,
            "dataplane_aead_worker_queue_wait",
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
        (Event::UdpRecvGroBatch, 44),
        (Event::UdpRecvGroPackets, 45),
        (Event::UdpRecvGroBytes, 46),
        (Event::UdpRecvPlainPackets, 47),
        (Event::TunReadPackets, 48),
        (Event::TunReadBytes, 49),
        (Event::TunWritePackets, 50),
        (Event::TunWriteBytes, 51),
        (Event::TunReadFrames, 52),
        (Event::TunReadFrameBytes, 53),
        (Event::TunWriteFrames, 54),
        (Event::TunWriteFrameBytes, 55),
        (Event::TunOutboundAdmissionDropped, 56),
        (Event::PendingTunSessionOldestDropped, 57),
        (Event::PendingTunSessionStaleDropped, 58),
        (Event::DataplaneFspPathOpen, 47),
        (Event::DataplaneFspPathOpenBulk, 53),
        (Event::DataplaneFspOwnerSyncCall, 57),
        (Event::DataplaneCryptoOpenBatch, 59),
        (Event::DataplaneCryptoSealPackets, 61),
        (Event::ReservedEvent199, 63),
        (Event::DataplaneFspOwnerSyncApplied, 65),
        (Event::PacketBatchPoolReuse, 67),
        (Event::PacketBufferPoolFresh, 71),
        (Event::UdpKernelDropped, 73),
        (Event::UdpSocketKernelDropped, 79),
        (Event::UdpNamespaceRcvbufErrors, 83),
        (Event::TunWriteBulkDropped, 89),
        (Event::TunWriteBulkBacklogHigh, 97),
        (Event::DataplaneTransportSendWorkerBackpressure, 101),
        (Event::DataplaneTransportSendWorkerDropped, 103),
        (Event::DataplaneTransportSendWorkerSendFailed, 107),
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
