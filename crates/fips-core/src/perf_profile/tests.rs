#[cfg(target_os = "linux")]
use super::udp_send_batch_tail_bucket_flags;
use super::{
    EVENTS, Event, HIST_BUCKETS, N_EVENTS, N_STAGES, Stage, TraceStamp, bucket_upper_ns,
    event_from_index, fmt_rate_per_sec, percentile_ns, record_event_count_sample,
    record_wait_threshold, stage_from_index,
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
    assert_eq!(N_EVENTS, 101);
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
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchBatch as usize).name(),
        "fmp_worker_dispatch_batch"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchPackets as usize).name(),
        "fmp_worker_dispatch_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInputWaitGe250us as usize).name(),
        "decrypt_worker_bulk_input_wait_ge250us"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInputWaitGe500us as usize).name(),
        "decrypt_worker_bulk_input_wait_ge500us"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInputWaitGe1ms as usize).name(),
        "decrypt_worker_bulk_input_wait_ge1ms"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOwnerSame as usize).name(),
        "decrypt_fsp_owner_same"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOwnerMismatch as usize).name(),
        "decrypt_fsp_owner_mismatch"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathLocal as usize).name(),
        "decrypt_fsp_path_local"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathHandoff as usize).name(),
        "decrypt_fsp_path_handoff"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathHelper as usize).name(),
        "decrypt_fsp_path_helper"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathFallback as usize).name(),
        "decrypt_fsp_path_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFmpPreownerHelper as usize).name(),
        "decrypt_fmp_preowner_helper"
    );
    assert_eq!(
        event_from_index(Event::DecryptFmpPreownerHelperFallback as usize).name(),
        "decrypt_fmp_preowner_helper_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFmpPreownerWindowFallback as usize).name(),
        "decrypt_fmp_preowner_window_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFmpPreownerInlineFallback as usize).name(),
        "decrypt_fmp_preowner_inline_fallback"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchFlowKeyed as usize).name(),
        "fmp_worker_dispatch_flow_keyed"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchTargetOnly as usize).name(),
        "fmp_worker_dispatch_target_only"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchWorker0 as usize).name(),
        "fmp_worker_dispatch_worker0"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchWorker7 as usize).name(),
        "fmp_worker_dispatch_worker7"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchWorkerOther as usize).name(),
        "fmp_worker_dispatch_worker_other"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReady as usize).name(),
        "fmp_aead_completion_ready"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionAccepted as usize).name(),
        "fmp_aead_completion_accepted"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionAeadFailed as usize).name(),
        "fmp_aead_completion_aead_failed"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDropped as usize).name(),
        "fmp_aead_completion_replay_dropped"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReadyMulti as usize).name(),
        "fmp_aead_completion_ready_multi"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReady as usize).name(),
        "fsp_aead_completion_ready"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAccepted as usize).name(),
        "fsp_aead_completion_accepted"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailed as usize).name(),
        "fsp_aead_completion_aead_failed"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDropped as usize).name(),
        "fsp_aead_completion_replay_dropped"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReadyMulti as usize).name(),
        "fsp_aead_completion_ready_multi"
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
    assert_eq!(N_STAGES, 64);
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
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerService as usize).name(),
        "decrypt_fsp_worker_service"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerBulkInputHeadWait as usize).name(),
        "decrypt_fsp_worker_bulk_input_head_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerBulkInputTailWait as usize).name(),
        "decrypt_fsp_worker_bulk_input_tail_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FspAeadHelperQueueWait as usize).name(),
        "fsp_aead_helper_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FspAeadHelperCompletionWait as usize).name(),
        "fsp_aead_helper_completion_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerFspSeal as usize).name(),
        "fmp_worker_fsp_seal"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerFmpSeal as usize).name(),
        "fmp_worker_fmp_seal"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerDispatch as usize).name(),
        "fmp_worker_dispatch"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerBulkInputHeadWait as usize).name(),
        "decrypt_worker_bulk_input_head_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerBulkInputTailWait as usize).name(),
        "decrypt_worker_bulk_input_tail_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerBulkItemService as usize).name(),
        "decrypt_worker_bulk_item_service"
    );
    assert_eq!(
        stage_from_index(Stage::FmpAeadHelperQueueWait as usize).name(),
        "fmp_aead_helper_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpAeadHelperCompletionWait as usize).name(),
        "fmp_aead_helper_completion_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpAeadHelperPriorityCompletionWait as usize).name(),
        "fmp_aead_helper_priority_completion_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpAeadHelperBulkCompletionWait as usize).name(),
        "fmp_aead_helper_bulk_completion_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpReceiveOrderWindowWait as usize).name(),
        "fmp_receive_order_window_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpAeadHelperCompletionService as usize).name(),
        "fmp_aead_helper_completion_service"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerOutputFlush as usize).name(),
        "decrypt_worker_output_flush"
    );
    assert_eq!(
        stage_from_index(Stage::FspAeadHelperCompletionService as usize).name(),
        "fsp_aead_helper_completion_service"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendPrepare as usize).name(),
        "endpoint_send_prepare"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendPlan as usize).name(),
        "endpoint_send_plan"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendCommit as usize).name(),
        "endpoint_send_commit"
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
    let dispatch_batch_before = EVENTS[Event::FmpWorkerDispatchBatch as usize].load(Relaxed);
    let dispatch_packets_before = EVENTS[Event::FmpWorkerDispatchPackets as usize].load(Relaxed);
    let decrypt_input_wait_ge250_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe250us as usize].load(Relaxed);
    let decrypt_input_wait_ge500_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe500us as usize].load(Relaxed);
    let decrypt_input_wait_ge1ms_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe1ms as usize].load(Relaxed);
    let fsp_owner_same_before = EVENTS[Event::DecryptFspOwnerSame as usize].load(Relaxed);
    let fsp_owner_mismatch_before = EVENTS[Event::DecryptFspOwnerMismatch as usize].load(Relaxed);
    let fsp_path_local_before = EVENTS[Event::DecryptFspPathLocal as usize].load(Relaxed);
    let fsp_path_handoff_before = EVENTS[Event::DecryptFspPathHandoff as usize].load(Relaxed);
    let fsp_path_helper_before = EVENTS[Event::DecryptFspPathHelper as usize].load(Relaxed);
    let fsp_path_fallback_before = EVENTS[Event::DecryptFspPathFallback as usize].load(Relaxed);
    let fmp_preowner_helper_before = EVENTS[Event::DecryptFmpPreownerHelper as usize].load(Relaxed);
    let fmp_preowner_helper_fallback_before =
        EVENTS[Event::DecryptFmpPreownerHelperFallback as usize].load(Relaxed);
    let fmp_preowner_window_fallback_before =
        EVENTS[Event::DecryptFmpPreownerWindowFallback as usize].load(Relaxed);
    let fmp_preowner_inline_fallback_before =
        EVENTS[Event::DecryptFmpPreownerInlineFallback as usize].load(Relaxed);
    let dispatch_flow_keyed_before =
        EVENTS[Event::FmpWorkerDispatchFlowKeyed as usize].load(Relaxed);
    let dispatch_target_only_before =
        EVENTS[Event::FmpWorkerDispatchTargetOnly as usize].load(Relaxed);
    let dispatch_worker0_before = EVENTS[Event::FmpWorkerDispatchWorker0 as usize].load(Relaxed);
    let dispatch_worker7_before = EVENTS[Event::FmpWorkerDispatchWorker7 as usize].load(Relaxed);
    let dispatch_worker_other_before =
        EVENTS[Event::FmpWorkerDispatchWorkerOther as usize].load(Relaxed);

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
    record_event_count_sample(Event::FmpWorkerDispatchBatch, 5);
    record_event_count_sample(Event::FmpWorkerDispatchPackets, 320);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe250us, 3);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe500us, 2);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe1ms, 1);
    record_event_count_sample(Event::DecryptFspOwnerSame, 71);
    record_event_count_sample(Event::DecryptFspOwnerMismatch, 73);
    record_event_count_sample(Event::DecryptFspPathLocal, 79);
    record_event_count_sample(Event::DecryptFspPathHandoff, 83);
    record_event_count_sample(Event::DecryptFspPathHelper, 89);
    record_event_count_sample(Event::DecryptFspPathFallback, 97);
    record_event_count_sample(Event::DecryptFmpPreownerHelper, 101);
    record_event_count_sample(Event::DecryptFmpPreownerHelperFallback, 103);
    record_event_count_sample(Event::DecryptFmpPreownerWindowFallback, 107);
    record_event_count_sample(Event::DecryptFmpPreownerInlineFallback, 109);
    record_event_count_sample(Event::FmpWorkerDispatchFlowKeyed, 113);
    record_event_count_sample(Event::FmpWorkerDispatchTargetOnly, 127);
    record_event_count_sample(Event::FmpWorkerDispatchWorker0, 131);
    record_event_count_sample(Event::FmpWorkerDispatchWorker7, 137);
    record_event_count_sample(Event::FmpWorkerDispatchWorkerOther, 139);

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
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchBatch as usize].load(Relaxed) - dispatch_batch_before,
        5
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchPackets as usize].load(Relaxed) - dispatch_packets_before,
        320
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe250us as usize].load(Relaxed)
            - decrypt_input_wait_ge250_before,
        3
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe500us as usize].load(Relaxed)
            - decrypt_input_wait_ge500_before,
        2
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe1ms as usize].load(Relaxed)
            - decrypt_input_wait_ge1ms_before,
        1
    );
    assert_eq!(
        EVENTS[Event::DecryptFspOwnerSame as usize].load(Relaxed) - fsp_owner_same_before,
        71
    );
    assert_eq!(
        EVENTS[Event::DecryptFspOwnerMismatch as usize].load(Relaxed) - fsp_owner_mismatch_before,
        73
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathLocal as usize].load(Relaxed) - fsp_path_local_before,
        79
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathHandoff as usize].load(Relaxed) - fsp_path_handoff_before,
        83
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathHelper as usize].load(Relaxed) - fsp_path_helper_before,
        89
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathFallback as usize].load(Relaxed) - fsp_path_fallback_before,
        97
    );
    assert_eq!(
        EVENTS[Event::DecryptFmpPreownerHelper as usize].load(Relaxed) - fmp_preowner_helper_before,
        101
    );
    assert_eq!(
        EVENTS[Event::DecryptFmpPreownerHelperFallback as usize].load(Relaxed)
            - fmp_preowner_helper_fallback_before,
        103
    );
    assert_eq!(
        EVENTS[Event::DecryptFmpPreownerWindowFallback as usize].load(Relaxed)
            - fmp_preowner_window_fallback_before,
        107
    );
    assert_eq!(
        EVENTS[Event::DecryptFmpPreownerInlineFallback as usize].load(Relaxed)
            - fmp_preowner_inline_fallback_before,
        109
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchFlowKeyed as usize].load(Relaxed)
            - dispatch_flow_keyed_before,
        113
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchTargetOnly as usize].load(Relaxed)
            - dispatch_target_only_before,
        127
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchWorker0 as usize].load(Relaxed) - dispatch_worker0_before,
        131
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchWorker7 as usize].load(Relaxed) - dispatch_worker7_before,
        137
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchWorkerOther as usize].load(Relaxed)
            - dispatch_worker_other_before,
        139
    );
}

#[test]
fn wait_threshold_events_only_count_samples_at_or_above_threshold() {
    let event = Event::ConnectedUdpActivationFailed;
    let before = EVENTS[event as usize].load(Relaxed);

    record_wait_threshold(event, 499_999, 3, 500_000);
    record_wait_threshold(event, 500_000, 5, 500_000);
    record_wait_threshold(event, 750_000, 7, 500_000);

    assert_eq!(EVENTS[event as usize].load(Relaxed) - before, 12);
}
