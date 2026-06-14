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
    assert_eq!(N_EVENTS, 100);
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
        event_from_index(Event::FmpLinuxBulkContainerEnqueued as usize).name(),
        "fmp_linux_bulk_container_enqueued"
    );
    assert_eq!(
        event_from_index(Event::FmpLinuxBulkContainerPackets as usize).name(),
        "fmp_linux_bulk_container_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpLinuxBulkContainerSkippedPackets as usize).name(),
        "fmp_linux_bulk_container_skipped_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpLinuxBulkContainerSent as usize).name(),
        "fmp_linux_bulk_container_sent"
    );
    assert_eq!(
        event_from_index(Event::FmpLinuxBulkContainerSentPackets as usize).name(),
        "fmp_linux_bulk_container_sent_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpLinuxBulkContainerEmpty as usize).name(),
        "fmp_linux_bulk_container_empty"
    );
    assert_eq!(
        event_from_index(Event::EndpointSendBatchCommand as usize).name(),
        "endpoint_send_batch_command"
    );
    assert_eq!(
        event_from_index(Event::EndpointSendBatchPackets as usize).name(),
        "endpoint_send_batch_packets"
    );
    assert_eq!(
        event_from_index(Event::EndpointSendBatchFull as usize).name(),
        "endpoint_send_batch_full"
    );
    assert_eq!(
        event_from_index(Event::EndpointSendBatchSingle as usize).name(),
        "endpoint_send_batch_single"
    );
    assert_eq!(
        event_from_index(Event::EndpointSendBatchPriorityPackets as usize).name(),
        "endpoint_send_batch_priority_packets"
    );
    assert_eq!(
        event_from_index(Event::EndpointSendBatchBulkPackets as usize).name(),
        "endpoint_send_batch_bulk_packets"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainDirectPriority as usize).name(),
        "rx_loop_endpoint_command_drain_direct_priority"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainDirectBulk as usize).name(),
        "rx_loop_endpoint_command_drain_direct_bulk"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainSide as usize).name(),
        "rx_loop_endpoint_command_drain_side"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainMaintenancePre as usize).name(),
        "rx_loop_endpoint_command_drain_maintenance_pre"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainMaintenancePost as usize).name(),
        "rx_loop_endpoint_command_drain_maintenance_post"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainSidePacket as usize).name(),
        "rx_loop_endpoint_command_drain_side_packet"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainSideDecryptPriority as usize).name(),
        "rx_loop_endpoint_command_drain_side_decrypt_priority"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainSideAuthenticatedBulk as usize).name(),
        "rx_loop_endpoint_command_drain_side_authenticated_bulk"
    );
    assert_eq!(
        event_from_index(Event::RxLoopEndpointCommandDrainSideDecryptBulk as usize).name(),
        "rx_loop_endpoint_command_drain_side_decrypt_bulk"
    );
    assert_eq!(
        event_from_index(Event::EncryptWorkerReliableBulkDropped as usize).name(),
        "encrypt_worker_reliable_bulk_dropped"
    );
    assert_eq!(
        event_from_index(Event::EncryptWorkerDiscardableBulkDropped as usize).name(),
        "encrypt_worker_discardable_bulk_dropped"
    );
    assert_eq!(
        event_from_index(Event::EndpointDirectFmpBatchFastPath as usize).name(),
        "endpoint_direct_fmp_batch_fast_path"
    );
    assert_eq!(
        event_from_index(Event::EndpointDirectFmpBatchFastPathPackets as usize).name(),
        "endpoint_direct_fmp_batch_fast_path_packets"
    );
    assert_eq!(
        event_from_index(Event::EndpointDirectFmpBatchFallback as usize).name(),
        "endpoint_direct_fmp_batch_fallback"
    );
    assert_eq!(
        event_from_index(Event::EndpointDirectFmpBatchFallbackPackets as usize).name(),
        "endpoint_direct_fmp_batch_fallback_packets"
    );
    assert_eq!(
        event_from_index(Event::EndpointDirectFmpBatchPartial as usize).name(),
        "endpoint_direct_fmp_batch_partial"
    );
    assert_eq!(
        event_from_index(Event::FmpLinuxBulkContainerQueueFull as usize).name(),
        "fmp_linux_bulk_container_queue_full"
    );
    assert_eq!(
        event_from_index(Event::FmpLinuxBulkContainerQueueFullPackets as usize).name(),
        "fmp_linux_bulk_container_queue_full_packets"
    );
    assert_eq!(
        event_from_index(Event::EndpointDirectFmpReceiveDropped as usize).name(),
        "endpoint_direct_fmp_receive_dropped"
    );
    assert_eq!(
        event_from_index(Event::EndpointDirectFmpReceiveDroppedPackets as usize).name(),
        "endpoint_direct_fmp_receive_dropped_packets"
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
    assert_eq!(N_STAGES, 82);
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
        stage_from_index(Stage::FmpWorkerFspSeal as usize).name(),
        "fmp_worker_fsp_seal"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerFmpSeal as usize).name(),
        "fmp_worker_fmp_seal"
    );
    assert_eq!(
        stage_from_index(Stage::FmpLinuxBulkContainerQueueWait as usize).name(),
        "fmp_linux_bulk_container_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpLinuxBulkContainerReadyWait as usize).name(),
        "fmp_linux_bulk_container_ready_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointRouteResolve as usize).name(),
        "endpoint_route_resolve"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSessionPrep as usize).name(),
        "endpoint_session_prep"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointRuntimeDispatchPrep as usize).name(),
        "endpoint_runtime_dispatch_prep"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointWorkerJobBuild as usize).name(),
        "endpoint_worker_job_build"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointWorkerCommit as usize).name(),
        "endpoint_worker_commit"
    );
    assert_eq!(
        stage_from_index(Stage::FmpLinuxBulkContainerSend as usize).name(),
        "fmp_linux_bulk_container_send"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandDirectPriorityWait as usize).name(),
        "endpoint_command_direct_priority_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandDirectBulkWait as usize).name(),
        "endpoint_command_direct_bulk_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandSideWait as usize).name(),
        "endpoint_command_side_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandMaintenancePreWait as usize).name(),
        "endpoint_command_maintenance_pre_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandMaintenancePostWait as usize).name(),
        "endpoint_command_maintenance_post_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpLinuxBulkContainerFirstSlotWait as usize).name(),
        "fmp_linux_bulk_container_first_slot_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpLinuxBulkContainerAllSlotsWait as usize).name(),
        "fmp_linux_bulk_container_all_slots_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandEnqueueWait as usize).name(),
        "endpoint_command_enqueue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointPriorityCommandEnqueueWait as usize).name(),
        "endpoint_priority_command_enqueue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointBulkCommandEnqueueWait as usize).name(),
        "endpoint_bulk_command_enqueue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandSidePacketWait as usize).name(),
        "endpoint_command_side_packet_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandSideDecryptPriorityWait as usize).name(),
        "endpoint_command_side_decrypt_priority_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandSideAuthenticatedBulkWait as usize).name(),
        "endpoint_command_side_authenticated_bulk_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointCommandSideDecryptBulkWait as usize).name(),
        "endpoint_command_side_decrypt_bulk_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendBatchService as usize).name(),
        "endpoint_send_batch_service"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendBatchFastPath as usize).name(),
        "endpoint_send_batch_fast_path"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendBatchSlowPath as usize).name(),
        "endpoint_send_batch_slow_path"
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
        stage_from_index(Stage::FmpReceiveOrderWindowWait as usize).name(),
        "fmp_receive_order_window_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedFmpReceiveWait as usize).name(),
        "decrypt_authenticated_fmp_receive_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptDirectFmpEndpointWait as usize).name(),
        "decrypt_direct_fmp_endpoint_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedSessionMessageWait as usize).name(),
        "decrypt_authenticated_session_message_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptDirectSessionCommitWait as usize).name(),
        "decrypt_direct_session_commit_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptDirectSessionDataWait as usize).name(),
        "decrypt_direct_session_data_wait"
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
        stage_from_index(Stage::FmpAeadHelperPriorityCompletionWait as usize).name(),
        "fmp_aead_helper_priority_completion_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpAeadHelperBulkCompletionWait as usize).name(),
        "fmp_aead_helper_bulk_completion_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerBulkItemService as usize).name(),
        "decrypt_worker_bulk_item_service"
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
    let encrypt_reliable_drop_before =
        EVENTS[Event::EncryptWorkerReliableBulkDropped as usize].load(Relaxed);
    let encrypt_discardable_drop_before =
        EVENTS[Event::EncryptWorkerDiscardableBulkDropped as usize].load(Relaxed);
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
    let linux_container_enqueued_before =
        EVENTS[Event::FmpLinuxBulkContainerEnqueued as usize].load(Relaxed);
    let linux_container_packets_before =
        EVENTS[Event::FmpLinuxBulkContainerPackets as usize].load(Relaxed);
    let linux_container_skipped_before =
        EVENTS[Event::FmpLinuxBulkContainerSkippedPackets as usize].load(Relaxed);
    let linux_container_sent_before =
        EVENTS[Event::FmpLinuxBulkContainerSent as usize].load(Relaxed);
    let linux_container_sent_packets_before =
        EVENTS[Event::FmpLinuxBulkContainerSentPackets as usize].load(Relaxed);
    let linux_container_empty_before =
        EVENTS[Event::FmpLinuxBulkContainerEmpty as usize].load(Relaxed);
    let linux_container_queue_full_before =
        EVENTS[Event::FmpLinuxBulkContainerQueueFull as usize].load(Relaxed);
    let linux_container_queue_full_packets_before =
        EVENTS[Event::FmpLinuxBulkContainerQueueFullPackets as usize].load(Relaxed);
    let endpoint_batch_command_before =
        EVENTS[Event::EndpointSendBatchCommand as usize].load(Relaxed);
    let endpoint_batch_packets_before =
        EVENTS[Event::EndpointSendBatchPackets as usize].load(Relaxed);
    let endpoint_batch_full_before = EVENTS[Event::EndpointSendBatchFull as usize].load(Relaxed);
    let endpoint_batch_single_before =
        EVENTS[Event::EndpointSendBatchSingle as usize].load(Relaxed);
    let endpoint_batch_priority_before =
        EVENTS[Event::EndpointSendBatchPriorityPackets as usize].load(Relaxed);
    let endpoint_batch_bulk_before =
        EVENTS[Event::EndpointSendBatchBulkPackets as usize].load(Relaxed);
    let endpoint_drain_direct_priority_before =
        EVENTS[Event::RxLoopEndpointCommandDrainDirectPriority as usize].load(Relaxed);
    let endpoint_drain_direct_bulk_before =
        EVENTS[Event::RxLoopEndpointCommandDrainDirectBulk as usize].load(Relaxed);
    let endpoint_drain_side_before =
        EVENTS[Event::RxLoopEndpointCommandDrainSide as usize].load(Relaxed);
    let endpoint_drain_side_packet_before =
        EVENTS[Event::RxLoopEndpointCommandDrainSidePacket as usize].load(Relaxed);
    let endpoint_drain_side_decrypt_priority_before =
        EVENTS[Event::RxLoopEndpointCommandDrainSideDecryptPriority as usize].load(Relaxed);
    let endpoint_drain_side_authenticated_bulk_before =
        EVENTS[Event::RxLoopEndpointCommandDrainSideAuthenticatedBulk as usize].load(Relaxed);
    let endpoint_drain_side_decrypt_bulk_before =
        EVENTS[Event::RxLoopEndpointCommandDrainSideDecryptBulk as usize].load(Relaxed);
    let endpoint_drain_maintenance_pre_before =
        EVENTS[Event::RxLoopEndpointCommandDrainMaintenancePre as usize].load(Relaxed);
    let endpoint_drain_maintenance_post_before =
        EVENTS[Event::RxLoopEndpointCommandDrainMaintenancePost as usize].load(Relaxed);
    let direct_fmp_fast_path_before =
        EVENTS[Event::EndpointDirectFmpBatchFastPath as usize].load(Relaxed);
    let direct_fmp_fast_path_packets_before =
        EVENTS[Event::EndpointDirectFmpBatchFastPathPackets as usize].load(Relaxed);
    let direct_fmp_fallback_before =
        EVENTS[Event::EndpointDirectFmpBatchFallback as usize].load(Relaxed);
    let direct_fmp_fallback_packets_before =
        EVENTS[Event::EndpointDirectFmpBatchFallbackPackets as usize].load(Relaxed);
    let direct_fmp_partial_before =
        EVENTS[Event::EndpointDirectFmpBatchPartial as usize].load(Relaxed);
    let direct_fmp_receive_dropped_before =
        EVENTS[Event::EndpointDirectFmpReceiveDropped as usize].load(Relaxed);
    let direct_fmp_receive_dropped_packets_before =
        EVENTS[Event::EndpointDirectFmpReceiveDroppedPackets as usize].load(Relaxed);
    let decrypt_worker_bulk_input_wait_ge250us_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe250us as usize].load(Relaxed);
    let decrypt_worker_bulk_input_wait_ge500us_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe500us as usize].load(Relaxed);
    let decrypt_worker_bulk_input_wait_ge1ms_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe1ms as usize].load(Relaxed);

    record_event_count_sample(Event::RxLoopSlowMaintenanceTimeout, 3);
    record_event_count_sample(Event::RxLoopSlowMaintenanceSkipped, 5);
    record_event_count_sample(Event::DecryptFallbackPressureDrain, 7);
    record_event_count_sample(Event::DecryptFallbackPriorityGated, 11);
    record_event_count_sample(Event::DecryptAuthenticatedSessionPriorityDropped, 13);
    record_event_count_sample(Event::DecryptAuthenticatedSessionBulkDropped, 17);
    record_event_count_sample(Event::EncryptWorkerQueueFull, 3);
    record_event_count_sample(Event::EncryptWorkerPriorityQueueFull, 1);
    record_event_count_sample(Event::EncryptWorkerBulkQueueFull, 2);
    record_event_count_sample(Event::EncryptWorkerReliableBulkDropped, 5);
    record_event_count_sample(Event::EncryptWorkerDiscardableBulkDropped, 7);
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
    record_event_count_sample(Event::FmpLinuxBulkContainerEnqueued, 5);
    record_event_count_sample(Event::FmpLinuxBulkContainerPackets, 320);
    record_event_count_sample(Event::FmpLinuxBulkContainerSkippedPackets, 7);
    record_event_count_sample(Event::FmpLinuxBulkContainerSent, 4);
    record_event_count_sample(Event::FmpLinuxBulkContainerSentPackets, 313);
    record_event_count_sample(Event::FmpLinuxBulkContainerEmpty, 1);
    record_event_count_sample(Event::FmpLinuxBulkContainerQueueFull, 2);
    record_event_count_sample(Event::FmpLinuxBulkContainerQueueFullPackets, 129);
    record_event_count_sample(Event::EndpointSendBatchCommand, 5);
    record_event_count_sample(Event::EndpointSendBatchPackets, 257);
    record_event_count_sample(Event::EndpointSendBatchFull, 4);
    record_event_count_sample(Event::EndpointSendBatchSingle, 1);
    record_event_count_sample(Event::EndpointSendBatchPriorityPackets, 9);
    record_event_count_sample(Event::EndpointSendBatchBulkPackets, 248);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainDirectPriority, 3);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainDirectBulk, 257);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainSide, 64);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainSidePacket, 41);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainSideDecryptPriority, 7);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainSideAuthenticatedBulk, 11);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainSideDecryptBulk, 5);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainMaintenancePre, 8);
    record_event_count_sample(Event::RxLoopEndpointCommandDrainMaintenancePost, 16);
    record_event_count_sample(Event::EndpointDirectFmpBatchFastPath, 3);
    record_event_count_sample(Event::EndpointDirectFmpBatchFastPathPackets, 192);
    record_event_count_sample(Event::EndpointDirectFmpBatchFallback, 2);
    record_event_count_sample(Event::EndpointDirectFmpBatchFallbackPackets, 65);
    record_event_count_sample(Event::EndpointDirectFmpBatchPartial, 1);
    record_event_count_sample(Event::EndpointDirectFmpReceiveDropped, 2);
    record_event_count_sample(Event::EndpointDirectFmpReceiveDroppedPackets, 129);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe250us, 3);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe500us, 2);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe1ms, 1);

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
        EVENTS[Event::EncryptWorkerReliableBulkDropped as usize].load(Relaxed)
            - encrypt_reliable_drop_before,
        5
    );
    assert_eq!(
        EVENTS[Event::EncryptWorkerDiscardableBulkDropped as usize].load(Relaxed)
            - encrypt_discardable_drop_before,
        7
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
        EVENTS[Event::FmpLinuxBulkContainerEnqueued as usize].load(Relaxed)
            - linux_container_enqueued_before,
        5
    );
    assert_eq!(
        EVENTS[Event::FmpLinuxBulkContainerPackets as usize].load(Relaxed)
            - linux_container_packets_before,
        320
    );
    assert_eq!(
        EVENTS[Event::FmpLinuxBulkContainerSkippedPackets as usize].load(Relaxed)
            - linux_container_skipped_before,
        7
    );
    assert_eq!(
        EVENTS[Event::FmpLinuxBulkContainerSent as usize].load(Relaxed)
            - linux_container_sent_before,
        4
    );
    assert_eq!(
        EVENTS[Event::FmpLinuxBulkContainerSentPackets as usize].load(Relaxed)
            - linux_container_sent_packets_before,
        313
    );
    assert_eq!(
        EVENTS[Event::FmpLinuxBulkContainerEmpty as usize].load(Relaxed)
            - linux_container_empty_before,
        1
    );
    assert_eq!(
        EVENTS[Event::FmpLinuxBulkContainerQueueFull as usize].load(Relaxed)
            - linux_container_queue_full_before,
        2
    );
    assert_eq!(
        EVENTS[Event::FmpLinuxBulkContainerQueueFullPackets as usize].load(Relaxed)
            - linux_container_queue_full_packets_before,
        129
    );
    assert_eq!(
        EVENTS[Event::EndpointSendBatchCommand as usize].load(Relaxed)
            - endpoint_batch_command_before,
        5
    );
    assert_eq!(
        EVENTS[Event::EndpointSendBatchPackets as usize].load(Relaxed)
            - endpoint_batch_packets_before,
        257
    );
    assert_eq!(
        EVENTS[Event::EndpointSendBatchFull as usize].load(Relaxed) - endpoint_batch_full_before,
        4
    );
    assert_eq!(
        EVENTS[Event::EndpointSendBatchSingle as usize].load(Relaxed)
            - endpoint_batch_single_before,
        1
    );
    assert_eq!(
        EVENTS[Event::EndpointSendBatchPriorityPackets as usize].load(Relaxed)
            - endpoint_batch_priority_before,
        9
    );
    assert_eq!(
        EVENTS[Event::EndpointSendBatchBulkPackets as usize].load(Relaxed)
            - endpoint_batch_bulk_before,
        248
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainDirectPriority as usize].load(Relaxed)
            - endpoint_drain_direct_priority_before,
        3
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainDirectBulk as usize].load(Relaxed)
            - endpoint_drain_direct_bulk_before,
        257
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainSide as usize].load(Relaxed)
            - endpoint_drain_side_before,
        64
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainSidePacket as usize].load(Relaxed)
            - endpoint_drain_side_packet_before,
        41
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainSideDecryptPriority as usize].load(Relaxed)
            - endpoint_drain_side_decrypt_priority_before,
        7
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainSideAuthenticatedBulk as usize].load(Relaxed)
            - endpoint_drain_side_authenticated_bulk_before,
        11
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainSideDecryptBulk as usize].load(Relaxed)
            - endpoint_drain_side_decrypt_bulk_before,
        5
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainMaintenancePre as usize].load(Relaxed)
            - endpoint_drain_maintenance_pre_before,
        8
    );
    assert_eq!(
        EVENTS[Event::RxLoopEndpointCommandDrainMaintenancePost as usize].load(Relaxed)
            - endpoint_drain_maintenance_post_before,
        16
    );
    assert_eq!(
        EVENTS[Event::EndpointDirectFmpBatchFastPath as usize].load(Relaxed)
            - direct_fmp_fast_path_before,
        3
    );
    assert_eq!(
        EVENTS[Event::EndpointDirectFmpBatchFastPathPackets as usize].load(Relaxed)
            - direct_fmp_fast_path_packets_before,
        192
    );
    assert_eq!(
        EVENTS[Event::EndpointDirectFmpBatchFallback as usize].load(Relaxed)
            - direct_fmp_fallback_before,
        2
    );
    assert_eq!(
        EVENTS[Event::EndpointDirectFmpBatchFallbackPackets as usize].load(Relaxed)
            - direct_fmp_fallback_packets_before,
        65
    );
    assert_eq!(
        EVENTS[Event::EndpointDirectFmpBatchPartial as usize].load(Relaxed)
            - direct_fmp_partial_before,
        1
    );
    assert_eq!(
        EVENTS[Event::EndpointDirectFmpReceiveDropped as usize].load(Relaxed)
            - direct_fmp_receive_dropped_before,
        2
    );
    assert_eq!(
        EVENTS[Event::EndpointDirectFmpReceiveDroppedPackets as usize].load(Relaxed)
            - direct_fmp_receive_dropped_packets_before,
        129
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe250us as usize].load(Relaxed)
            - decrypt_worker_bulk_input_wait_ge250us_before,
        3
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe500us as usize].load(Relaxed)
            - decrypt_worker_bulk_input_wait_ge500us_before,
        2
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe1ms as usize].load(Relaxed)
            - decrypt_worker_bulk_input_wait_ge1ms_before,
        1
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
