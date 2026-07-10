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
fn event_table_is_exhaustive() {
    assert_eq!(N_EVENTS, 269);
    for index in 0..N_EVENTS {
        let event = event_from_index(index);
        assert_eq!(event as usize, index);
        assert!(!event.name().is_empty());
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
            Stage::DataplaneTransportSendBatch,
            "dataplane_transport_send_batch",
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
        (Event::EndpointDataBatchDropped, 17),
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
        (Event::ReservedEvent210, 101),
        (Event::ReservedEvent211, 103),
        (Event::DataplaneTransportSendFailed, 107),
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
