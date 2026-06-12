#[cfg(target_os = "linux")]
use super::udp_send_batch_tail_bucket_flags;
use super::{
    EVENTS, Event, HIST_BUCKETS, N_EVENTS, N_STAGES, Stage, TraceStamp, bucket_upper_ns,
    event_from_index, fmt_rate_per_sec, percentile_ns, record_event_count_sample, stage_from_index,
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
fn event_table_exposes_liveness_and_send_path_events() {
    assert_eq!(N_EVENTS, 65);
    assert_eq!(
        event_from_index(Event::DecryptFallbackBacklogHigh as usize).name(),
        "decrypt_fallback_backlog_high"
    );
    assert_eq!(
        event_from_index(Event::RxLoopSlowMaintenanceTimeout as usize).name(),
        "rx_loop_slow_maintenance_timeout"
    );
    assert_eq!(
        event_from_index(Event::RxLoopSlowMaintenanceSkipped as usize).name(),
        "rx_loop_slow_maintenance_skipped"
    );
    assert_eq!(
        event_from_index(Event::DecryptFallbackPressureDrain as usize).name(),
        "decrypt_fallback_pressure_drain"
    );
    assert_eq!(
        event_from_index(Event::DecryptFallbackPriorityGated as usize).name(),
        "decrypt_fallback_priority_gated"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPriorityQueueFullFallback as usize).name(),
        "decrypt_fsp_priority_queue_full_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspBulkQueueFullFallback as usize).name(),
        "decrypt_fsp_bulk_queue_full_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspWorkerReplayDropped as usize).name(),
        "decrypt_fsp_worker_replay_dropped"
    );
    assert_eq!(
        event_from_index(Event::DecryptAuthenticatedSessionPriorityDropped as usize).name(),
        "decrypt_authenticated_session_priority_dropped"
    );
    assert_eq!(
        event_from_index(Event::DecryptAuthenticatedSessionBulkDropped as usize).name(),
        "decrypt_authenticated_session_bulk_dropped"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchFlush as usize).name(),
        "fmp_worker_batch_flush"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchPackets as usize).name(),
        "fmp_worker_batch_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchFull as usize).name(),
        "fmp_worker_batch_full"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchSingle as usize).name(),
        "fmp_worker_batch_single"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchPriorityPackets as usize).name(),
        "fmp_worker_batch_priority_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchBulkPackets as usize).name(),
        "fmp_worker_batch_bulk_packets"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoBatch as usize).name(),
        "udp_send_gso_batch"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoPackets as usize).name(),
        "udp_send_gso_packets"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgBatch as usize).name(),
        "udp_send_sendmmsg_batch"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgPackets as usize).name(),
        "udp_send_sendmmsg_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchFlush as usize).name(),
        "decrypt_worker_batch_flush"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchPackets as usize).name(),
        "decrypt_worker_batch_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchFull as usize).name(),
        "decrypt_worker_batch_full"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchSingle as usize).name(),
        "decrypt_worker_batch_single"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchPriorityPackets as usize).name(),
        "decrypt_worker_batch_priority_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchBulkPackets as usize).name(),
        "decrypt_worker_batch_bulk_packets"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoBatchGe32 as usize).name(),
        "udp_send_gso_batch_ge32"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoBatchGe48 as usize).name(),
        "udp_send_gso_batch_ge48"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoBatchEq64 as usize).name(),
        "udp_send_gso_batch_eq64"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgBatchGe32 as usize).name(),
        "udp_send_sendmmsg_batch_ge32"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgBatchGe48 as usize).name(),
        "udp_send_sendmmsg_batch_ge48"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgBatchEq64 as usize).name(),
        "udp_send_sendmmsg_batch_eq64"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroup as usize).name(),
        "fmp_send_group"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroupPackets as usize).name(),
        "fmp_send_group_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroupSingle as usize).name(),
        "fmp_send_group_single"
    );
    assert_eq!(
        event_from_index(Event::EncryptWorkerPriorityQueueFull as usize).name(),
        "encrypt_worker_priority_queue_full"
    );
    assert_eq!(
        event_from_index(Event::EncryptWorkerBulkQueueFull as usize).name(),
        "encrypt_worker_bulk_queue_full"
    );
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
fn stage_table_exposes_endpoint_command_lane_waits() {
    assert_eq!(N_STAGES, 42);
    assert_eq!(
        stage_from_index(Stage::EndpointCommandWait as usize).name(),
        "endpoint_command_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointPriorityCommandWait as usize).name(),
        "endpoint_priority_command_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointBulkCommandWait as usize).name(),
        "endpoint_bulk_command_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedSessionWait as usize).name(),
        "decrypt_authenticated_session_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedSessionPriorityWait as usize).name(),
        "decrypt_authenticated_session_priority_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedSessionBulkWait as usize).name(),
        "decrypt_authenticated_session_bulk_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerQueueWait as usize).name(),
        "decrypt_fsp_worker_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerPriorityQueueWait as usize).name(),
        "decrypt_fsp_worker_priority_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerBulkQueueWait as usize).name(),
        "decrypt_fsp_worker_bulk_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerPriorityQueueWait as usize).name(),
        "fmp_worker_priority_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerBulkQueueWait as usize).name(),
        "fmp_worker_bulk_queue_wait"
    );
}

#[test]
fn rx_loop_liveness_and_fallback_pressure_events_increment_counters() {
    let timeout_before = EVENTS[Event::RxLoopSlowMaintenanceTimeout as usize].load(Relaxed);
    let skipped_before = EVENTS[Event::RxLoopSlowMaintenanceSkipped as usize].load(Relaxed);
    let pressure_before = EVENTS[Event::DecryptFallbackPressureDrain as usize].load(Relaxed);
    let gated_before = EVENTS[Event::DecryptFallbackPriorityGated as usize].load(Relaxed);
    let auth_priority_before =
        EVENTS[Event::DecryptAuthenticatedSessionPriorityDropped as usize].load(Relaxed);
    let auth_bulk_before =
        EVENTS[Event::DecryptAuthenticatedSessionBulkDropped as usize].load(Relaxed);
    let encrypt_queue_full_before = EVENTS[Event::EncryptWorkerQueueFull as usize].load(Relaxed);
    let encrypt_priority_full_before =
        EVENTS[Event::EncryptWorkerPriorityQueueFull as usize].load(Relaxed);
    let encrypt_bulk_full_before = EVENTS[Event::EncryptWorkerBulkQueueFull as usize].load(Relaxed);
    let batch_flush_before = EVENTS[Event::FmpWorkerBatchFlush as usize].load(Relaxed);
    let batch_packets_before = EVENTS[Event::FmpWorkerBatchPackets as usize].load(Relaxed);
    let batch_full_before = EVENTS[Event::FmpWorkerBatchFull as usize].load(Relaxed);
    let batch_single_before = EVENTS[Event::FmpWorkerBatchSingle as usize].load(Relaxed);
    let batch_priority_before = EVENTS[Event::FmpWorkerBatchPriorityPackets as usize].load(Relaxed);
    let batch_bulk_before = EVENTS[Event::FmpWorkerBatchBulkPackets as usize].load(Relaxed);
    let gso_batch_before = EVENTS[Event::UdpSendGsoBatch as usize].load(Relaxed);
    let gso_packets_before = EVENTS[Event::UdpSendGsoPackets as usize].load(Relaxed);
    let sendmmsg_batch_before = EVENTS[Event::UdpSendSendmmsgBatch as usize].load(Relaxed);
    let sendmmsg_packets_before = EVENTS[Event::UdpSendSendmmsgPackets as usize].load(Relaxed);
    let decrypt_batch_flush_before = EVENTS[Event::DecryptWorkerBatchFlush as usize].load(Relaxed);
    let decrypt_batch_packets_before =
        EVENTS[Event::DecryptWorkerBatchPackets as usize].load(Relaxed);
    let decrypt_batch_full_before = EVENTS[Event::DecryptWorkerBatchFull as usize].load(Relaxed);
    let decrypt_batch_single_before =
        EVENTS[Event::DecryptWorkerBatchSingle as usize].load(Relaxed);
    let decrypt_batch_priority_before =
        EVENTS[Event::DecryptWorkerBatchPriorityPackets as usize].load(Relaxed);
    let decrypt_batch_bulk_before =
        EVENTS[Event::DecryptWorkerBatchBulkPackets as usize].load(Relaxed);

    record_event_count_sample(Event::RxLoopSlowMaintenanceTimeout, 3);
    record_event_count_sample(Event::RxLoopSlowMaintenanceSkipped, 5);
    record_event_count_sample(Event::DecryptFallbackPressureDrain, 7);
    record_event_count_sample(Event::DecryptFallbackPriorityGated, 11);
    record_event_count_sample(Event::DecryptAuthenticatedSessionPriorityDropped, 13);
    record_event_count_sample(Event::DecryptAuthenticatedSessionBulkDropped, 17);
    record_event_count_sample(Event::EncryptWorkerQueueFull, 3);
    record_event_count_sample(Event::EncryptWorkerPriorityQueueFull, 1);
    record_event_count_sample(Event::EncryptWorkerBulkQueueFull, 2);
    record_event_count_sample(Event::FmpWorkerBatchFlush, 19);
    record_event_count_sample(Event::FmpWorkerBatchPackets, 23);
    record_event_count_sample(Event::FmpWorkerBatchFull, 29);
    record_event_count_sample(Event::FmpWorkerBatchSingle, 31);
    record_event_count_sample(Event::FmpWorkerBatchPriorityPackets, 37);
    record_event_count_sample(Event::FmpWorkerBatchBulkPackets, 41);
    record_event_count_sample(Event::UdpSendGsoBatch, 43);
    record_event_count_sample(Event::UdpSendGsoPackets, 47);
    record_event_count_sample(Event::UdpSendSendmmsgBatch, 53);
    record_event_count_sample(Event::UdpSendSendmmsgPackets, 59);
    record_event_count_sample(Event::DecryptWorkerBatchFlush, 2);
    record_event_count_sample(Event::DecryptWorkerBatchPackets, 65);
    record_event_count_sample(Event::DecryptWorkerBatchFull, 1);
    record_event_count_sample(Event::DecryptWorkerBatchSingle, 1);
    record_event_count_sample(Event::DecryptWorkerBatchPriorityPackets, 3);
    record_event_count_sample(Event::DecryptWorkerBatchBulkPackets, 62);

    assert_eq!(
        EVENTS[Event::RxLoopSlowMaintenanceTimeout as usize].load(Relaxed) - timeout_before,
        3
    );
    assert_eq!(
        EVENTS[Event::RxLoopSlowMaintenanceSkipped as usize].load(Relaxed) - skipped_before,
        5
    );
    assert_eq!(
        EVENTS[Event::DecryptFallbackPressureDrain as usize].load(Relaxed) - pressure_before,
        7
    );
    assert_eq!(
        EVENTS[Event::DecryptFallbackPriorityGated as usize].load(Relaxed) - gated_before,
        11
    );
    assert_eq!(
        EVENTS[Event::DecryptAuthenticatedSessionPriorityDropped as usize].load(Relaxed)
            - auth_priority_before,
        13
    );
    assert_eq!(
        EVENTS[Event::DecryptAuthenticatedSessionBulkDropped as usize].load(Relaxed)
            - auth_bulk_before,
        17
    );
    assert_eq!(
        EVENTS[Event::EncryptWorkerQueueFull as usize].load(Relaxed) - encrypt_queue_full_before,
        3
    );
    assert_eq!(
        EVENTS[Event::EncryptWorkerPriorityQueueFull as usize].load(Relaxed)
            - encrypt_priority_full_before,
        1
    );
    assert_eq!(
        EVENTS[Event::EncryptWorkerBulkQueueFull as usize].load(Relaxed) - encrypt_bulk_full_before,
        2
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchFlush as usize].load(Relaxed) - batch_flush_before,
        19
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchPackets as usize].load(Relaxed) - batch_packets_before,
        23
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchFull as usize].load(Relaxed) - batch_full_before,
        29
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchSingle as usize].load(Relaxed) - batch_single_before,
        31
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchPriorityPackets as usize].load(Relaxed) - batch_priority_before,
        37
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchBulkPackets as usize].load(Relaxed) - batch_bulk_before,
        41
    );
    assert_eq!(
        EVENTS[Event::UdpSendGsoBatch as usize].load(Relaxed) - gso_batch_before,
        43
    );
    assert_eq!(
        EVENTS[Event::UdpSendGsoPackets as usize].load(Relaxed) - gso_packets_before,
        47
    );
    assert_eq!(
        EVENTS[Event::UdpSendSendmmsgBatch as usize].load(Relaxed) - sendmmsg_batch_before,
        53
    );
    assert_eq!(
        EVENTS[Event::UdpSendSendmmsgPackets as usize].load(Relaxed) - sendmmsg_packets_before,
        59
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchFlush as usize].load(Relaxed) - decrypt_batch_flush_before,
        2
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchPackets as usize].load(Relaxed)
            - decrypt_batch_packets_before,
        65
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchFull as usize].load(Relaxed) - decrypt_batch_full_before,
        1
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchSingle as usize].load(Relaxed)
            - decrypt_batch_single_before,
        1
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchPriorityPackets as usize].load(Relaxed)
            - decrypt_batch_priority_before,
        3
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchBulkPackets as usize].load(Relaxed)
            - decrypt_batch_bulk_before,
        62
    );
}
